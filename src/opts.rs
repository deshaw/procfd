use clap::Parser;
use eyre::Result;
use regex::Regex;
use uzers::get_user_by_name;

use crate::{FDType, FDSocketDomainFilter, FDSocketTypeFilter, ProcessInfo};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    // Filter by process ID
    #[clap(short, long, display_order = 1, help = "Filter by process ID")]
    pub pid: Option<i32>,

    #[clap(
        short,
        long = "user",
        value_name = "USER",
        display_order = 2,
        value_parser = validate_user,
        help = "Filter by username"
    )]
    pub uid: Option<u32>,

    #[clap(
        short,
        long,
        display_order = 3,
        value_parser = validate_cmd,
        help = "Filter by exact command name. Use /cmd/ for regex match."
    )]
    pub cmd: Option<Regex>,

    #[clap(
        long = "type",
        value_name = "TYPE",
        display_order = 4,
        help = "Filter by file descriptor type"
    )]
    pub type_: Option<FDType>,

    #[clap(
        long = "socket-domain",
        value_name = "DOMAIN",
        display_order = 5,
        help = "Filter by socket domain"
    )]
    pub socket_domain: Option<FDSocketDomainFilter>,

    #[clap(
        long = "socket-type",
        value_name = "TYPE",
        display_order = 6,
        help = "Filter by socket type"
    )]
    pub socket_type: Option<FDSocketTypeFilter>,

    #[clap(
        long = "socket-state",
        display_order = 7,
        help = "Filter by socket state"
    )]
    pub socket_state: Option<String>,

    #[clap(long, display_order = 8, help = "Filter by source or destination port")]
    pub port: Option<u16>,

    #[clap(
        long,
        display_order = 9,
        conflicts_with = "port",
        help = "Filter by source port"
    )]
    pub src_port: Option<u16>,

    #[clap(
        long,
        display_order = 10,
        conflicts_with = "port",
        help = "Filter by destination port"
    )]
    pub dst_port: Option<u16>,

    #[clap(
        long,
        display_order = 11,
        help = "Filter by source or destination host/ip"
    )]
    pub host: Option<String>,

    #[clap(
        long,
        display_order = 12,
        conflicts_with = "host",
        help = "Filter by source host/ip"
    )]
    pub src_host: Option<String>,

    #[clap(
        long,
        display_order = 13,
        conflicts_with = "host",
        help = "Filter by destination host/ip"
    )]
    pub dst_host: Option<String>,

    #[clap(long, display_order = 14, help = "Disable DNS lookups")]
    pub no_dns: bool,

    // output options
    #[clap(
        long,
        display_order = 15,
        conflicts_with = "pid_only",
        help = "Render results as JSON"
    )]
    pub json: bool,

    #[clap(
        long,
        display_order = 16,
        conflicts_with = "json",
        help = "Only show PIDs"
    )]
    pub pid_only: bool,
}

impl Args {
    // Return true if the process matches --pid/--user/--cmd filters
    pub(crate) fn filter_process(&self, process: &ProcessInfo) -> bool {
        if self.pid.is_some_and(|pid| pid != process.pid) {
            return false;
        }
        if self.uid.is_some_and(|uid| uid != process.uid) {
            return false;
        }
        if self
            .cmd
            .as_ref()
            .is_some_and(|cmd| !cmd.is_match(&process.comm))
        {
            return false;
        }
        true
    }
}

// Validate --cmd flag, convert to regex
fn validate_cmd(s: &str) -> Result<Regex, String> {
    let cmd = s.to_string();
    if cmd.starts_with('/') && cmd.ends_with('/') {
        Regex::new(cmd.trim_matches('/')).map_err(|_| "invalid regex".to_string())
    } else {
        // For simplicity, if no / delimiters, treat input as an exact regex match
        let exact_match_re = format!("^{}$", regex::escape(s));
        Regex::new(&exact_match_re).map_err(|_| "invalid regex".to_string())
    }
}

fn validate_user(s: &str) -> Result<u32, String> {
    if let Some(user) = get_user_by_name(s) {
        Ok(user.uid())
    } else {
        Err("invalid user".to_string())
    }
}
