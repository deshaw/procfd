#[macro_use]
extern crate prettytable;
use clap::Parser;
use eyre::{Result, WrapErr};
use itertools::Itertools;
use prettytable::format;
use prettytable::{Cell, Row, Table};
use procfd::{get_fd_entries, Args};
use std::collections::HashSet;
use std::env;
use std::thread;

const MAX_THREADS: usize = 8;

pub fn clear_environment() {
    for (key, _) in env::vars() {
        env::remove_var(key);
    }
}

// Limit parallelism to no more than 8 threads
// Anything higher doesn't yield any performance benefits
#[allow(clippy::missing_panics_doc)]
pub fn configure_parallelism() {
    let num_cores = thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);

    let num_threads = std::cmp::min(MAX_THREADS, num_cores);
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .expect("Error configuring rayon thread pool");
}

fn main() -> Result<()> {
    // As a general security practice, clear the environment in case the command is run privileged
    clear_environment();

    configure_parallelism();

    let args = Args::parse();
    let all_fds = get_fd_entries(&args)?;

    if args.json {
        let serialized = serde_json::to_string(&all_fds).wrap_err("Error serializing json")?;
        println!("{serialized}");
    } else if args.pid_only {
        let unique_pids: HashSet<i32> = all_fds.iter().map(|fd| fd.pid).collect();
        for pid in unique_pids.into_iter().sorted() {
            println!("{pid}");
        }
    } else if !all_fds.is_empty() {
        // Render table
        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
        table.set_titles(row!("PID", "User", "Name", "Type", "FD", "Mode", "Target"));
        for fd_entry in &all_fds {
            let fd_str = match fd_entry.fd {
                Some(fd) => format!("{fd}"),
                None => String::new(),
            };
            let mode_str = fd_entry.mode.clone().unwrap_or_default();
            table.add_row(Row::new(vec![
                Cell::new(format!("{}", fd_entry.pid).as_str()),
                Cell::new(fd_entry.user.as_str()),
                Cell::new(fd_entry.name.as_str()),
                Cell::new(fd_entry.fd_type().as_str()),
                Cell::new(fd_str.as_str()),
                Cell::new(mode_str.as_str()),
                Cell::new(format!("{}", fd_entry.target).as_str()),
            ]));
        }
        table.printstd();
    }
    Ok(())
}
