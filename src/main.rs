#[macro_use]
extern crate prettytable;
use clap::{Parser, ValueEnum};
use dashmap::setref::multiple::RefMulti;
use dashmap::DashSet;
use eyre::{bail, Result, WrapErr};
use itertools::Itertools;
use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_sock_diag::{
    constants as sock_diag_constants,
    unix::{ShowFlags, StateFlags, UnixRequest},
    SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr as NlSocketAddr};
use prettytable::format;
use prettytable::{Cell, Row, Table};
use procfs::net;
use procfs::process::{self, FDInfo, FDPermissions};
use rayon::prelude::*;
use regex::Regex;
use serde_derive::Serialize;
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Not;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use uzers::{get_user_by_name, get_user_by_uid};

const READ: FDPermissions = FDPermissions::READ;
const SOCKET_TYPES: [&str; 6] = ["", "stream", "dgram", "raw", "rdm", "seqpacket"];

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // Filter by process ID
    #[clap(short, long, display_order = 1, help = "Filter by process ID")]
    pid: Option<i32>,

    #[clap(
        short,
        long = "user",
        value_name = "USER",
        display_order = 2,
        value_parser = validate_user,
        help = "Filter by username"
    )]
    uid: Option<u32>,

    #[clap(
        short,
        long,
        display_order = 3,
        value_parser = validate_cmd,
        help = "Filter by exact command name. Use /cmd/ for regex match."
    )]
    cmd: Option<Regex>,

    #[clap(
        long = "type",
        value_name = "TYPE",
        display_order = 4,
        help = "Filter by file descriptor type"
    )]
    type_: Option<FDType>,

    #[clap(
        long = "socket-domain",
        value_name = "DOMAIN",
        display_order = 5,
        help = "Filter by socket domain"
    )]
    socket_domain: Option<FDSocketDomainFilter>,

    #[clap(
        long = "socket-type",
        value_name = "TYPE",
        display_order = 6,
        help = "Filter by socket type"
    )]
    socket_type: Option<FDSocketTypeFilter>,

    #[clap(
        long = "socket-state",
        display_order = 7,
        help = "Filter by socket state"
    )]
    socket_state: Option<String>,

    #[clap(long, display_order = 8, help = "Filter by source or destination port")]
    port: Option<u16>,

    #[clap(
        long,
        display_order = 9,
        conflicts_with = "port",
        help = "Filter by source port"
    )]
    src_port: Option<u16>,

    #[clap(
        long,
        display_order = 10,
        conflicts_with = "port",
        help = "Filter by destination port"
    )]
    dst_port: Option<u16>,

    #[clap(
        long,
        display_order = 11,
        help = "Filter by source or destination host/ip"
    )]
    host: Option<String>,

    #[clap(
        long,
        display_order = 12,
        conflicts_with = "host",
        help = "Filter by source host/ip"
    )]
    src_host: Option<String>,

    #[clap(
        long,
        display_order = 13,
        conflicts_with = "host",
        help = "Filter by destination host/ip"
    )]
    dst_host: Option<String>,

    #[clap(long, display_order = 14, help = "Disable DNS lookups")]
    no_dns: bool,

    // output options
    #[clap(long, display_order = 15, help = "Render results as JSON")]
    json: bool,
}

impl Args {
    // Return true if the process matches --pid/--user/--cmd filters
    fn filter_process(&self, process: &ProcessInfo) -> bool {
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

#[allow(clippy::struct_field_names)]
struct NetMaps {
    tcp_map: HashMap<u64, net::TcpNetEntry>,
    udp_map: HashMap<u64, net::UdpNetEntry>,
    unix_map: HashMap<u64, UnixSocketEntry>,
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum FDType {
    Socket,
    Cwd,
    Root,
    Exe,
    Path,
    Pipe,
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum FDSocketDomainFilter {
    Inet,
    Inet4,
    Inet6,
    Unix,
    Other,
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Serialize)]
enum FDSocketDomain {
    #[serde(rename = "inet")]
    Inet,
    #[serde(rename = "unix")]
    Unix,
    // Other could be NETLINK (currently unsupported)
    #[serde(rename = "other")]
    Other,
}

impl fmt::Display for FDSocketDomain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FDSocketDomain::Inet => write!(f, "inet"),
            FDSocketDomain::Unix => write!(f, "unix"),
            FDSocketDomain::Other => write!(f, "other"),
        }
    }
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Serialize)]
enum FDSocketTypeFilter {
    UnixStream,
    UnixDgram,
    Tcp,
    Udp,
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Serialize)]
enum FDSocketProtocol {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
    // Not implemented: sctp, icmp, raw
}

impl fmt::Display for FDSocketProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            FDSocketProtocol::Tcp => "tcp".to_string(),
            FDSocketProtocol::Udp => "udp".to_string(),
        };
        write!(f, "{msg}")
    }
}

#[derive(Serialize, Debug, Copy, Clone, PartialEq)]
enum IpVersion {
    #[serde(rename = "4")]
    V4,
    #[serde(rename = "6")]
    V6,
}

#[derive(Serialize, Debug)]
struct NetConnEntry {
    // Note that local_host and remote_host fields are not populated as part of NetConnEntry initialization
    // and are filled in later by the resolve_hostname method to support lazy DNS lookups.
    // We're still adding them as a field in the struct to use the default serde seralizer.
    local_ip: IpAddr,
    local_host: String,
    local_port: u16,
    remote_ip: IpAddr,
    remote_host: String,
    remote_port: u16,
    state: String,
    ip_version: IpVersion,
    protocol: FDSocketProtocol,
    #[serde(skip)]
    dns_lookup: bool,
}

impl NetConnEntry {
    fn resolve_hostname(&mut self) {
        if self.remote_host.is_empty() {
            // Treat DNS lookup errors as an empty string, as it's only used for display purposes.
            self.remote_host = dns_lookup::lookup_addr(&self.remote_ip).unwrap_or_default();
        }
        if self.local_host.is_empty() {
            // Treat DNS lookup errors as an empty string, as it's only used for display purposes.
            self.local_host = dns_lookup::lookup_addr(&self.local_ip).unwrap_or_default();
        }
    }
}

impl fmt::Display for NetConnEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let format_ip = |ip: &IpAddr| match ip {
            IpAddr::V4(_) => format!("{ip}"),
            // IPv6 addresses are enclosed in []
            IpAddr::V6(_) => format!("[{ip}]"),
        };
        let ipv4_zero_addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let ipv6_zero_addr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        let local_host = if self.local_host.is_empty() {
            format_ip(&self.local_ip)
        } else {
            self.local_host.clone()
        };
        let remote_host = if self.remote_host.is_empty() {
            format_ip(&self.remote_ip)
        } else {
            self.remote_host.clone()
        };
        let protocol = match (self.protocol, self.ip_version) {
            (FDSocketProtocol::Tcp, IpVersion::V4) => "TCP",
            (FDSocketProtocol::Udp, IpVersion::V4) => "UDP",
            (FDSocketProtocol::Tcp, IpVersion::V6) => "TCP6",
            (FDSocketProtocol::Udp, IpVersion::V6) => "UDP6",
        };
        if self.remote_ip == ipv4_zero_addr || self.remote_ip == ipv6_zero_addr {
            // Nothing on the remote side, so don't display it
            // Display state only for TCP (UDP state would indicate CLOSE, which is confusing and not useful)
            let state_opt = if self.protocol == FDSocketProtocol::Tcp {
                format!(" ({})", self.state)
            } else {
                String::new()
            };
            write!(
                f,
                "{}: {}:{}{}",
                protocol, local_host, self.local_port, state_opt
            )
        } else {
            write!(
                f,
                "{}: {}:{} -> {}:{} ({})",
                protocol, local_host, self.local_port, remote_host, self.remote_port, self.state
            )
        }
    }
}

fn to_net_conn_entry(
    local_address: SocketAddr,
    remote_address: SocketAddr,
    state: &str,
    protocol: FDSocketProtocol,
    dns_lookup: bool,
) -> NetConnEntry {
    NetConnEntry {
        local_ip: local_address.ip(),
        remote_ip: remote_address.ip(),
        local_port: local_address.port(),
        remote_port: remote_address.port(),
        local_host: String::new(),  // will be populated later
        remote_host: String::new(), // will be populated later
        state: state.to_uppercase(),
        ip_version: match local_address.ip() {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        },
        protocol,
        dns_lookup,
    }
}

#[derive(Serialize, Debug, Clone)]
struct UnixSocketEntry {
    #[serde(rename = "type")]
    socket_type: String,
    path: Option<String>,
    state: String,
    peer: Option<SocketEndpoint>,
}

impl fmt::Display for UnixSocketEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut msg = match &self.path {
            // Use lossy conversion because the results need to be exportable as json, which is UTF8
            Some(path) => format!("{}:{}", self.socket_type, path),
            None => self.socket_type.clone(),
        };
        if let Some(peer) = &self.peer {
            // Group endpoints by name and pid
            // Eg: Display foo[123][4],foo[123][5] as foo[123][4,5]
            // Use chunk_by since endpoints are already sorted by (pid, fd)
            // name is already unique for a given pid, so it's not necessary to group by name
            let parts: Vec<String> = peer
                .endpoints
                .iter()
                .chunk_by(|a| a.pid)
                .into_iter()
                .map(|(_, endpoints)| {
                    let endpoints: Vec<&FDEndpoint> = endpoints.into_iter().collect();
                    let fds: Vec<String> = endpoints.iter().map(|e| e.fd.to_string()).collect();
                    format!("{}[{}][{}]", endpoints[0].name, endpoints[0].pid, fds.join(","))
                })
                .collect();

            let peer_endpoints = format!(" -> {}", parts.join(","));
            msg.push_str(&peer_endpoints);

            if let Some(path) = &peer.path {
                let m = format!(" ({path})");
                msg.push_str(&m);
            }
        }
        let m = format!(" ({})", self.state);
        msg.push_str(&m);
        write!(f, "{msg}")
    }
}

#[derive(Serialize, Debug)]
enum SocketEntry {
    #[serde(rename = "inet")]
    Inet(NetConnEntry),
    #[serde(rename = "unix")]
    Unix(UnixSocketEntry),
}

impl fmt::Display for SocketEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            SocketEntry::Inet(e) => format!("{e}"),
            SocketEntry::Unix(e) => format!("{e}"),
        };
        write!(f, "{msg}")
    }
}

#[derive(Serialize, Debug)]
struct PipeInfo {
    inode: u64,
    mode: char,
    endpoints: Vec<PipeTarget>,
    #[serde(skip)]
    self_pid: i32,
}

#[derive(Serialize, Debug, Clone)]
struct PipeTarget {
    pid: i32,
    name: String,
    fd: i32,
    mode: char,
}

#[derive(Serialize, Debug, Clone)]
struct SocketEndpoint {
    inode: u64,
    path: Option<String>,
    endpoints: Vec<FDEndpoint>,
}

#[derive(Serialize, Debug, Clone)]
struct FDEndpoint {
    pid: i32,
    name: String,
    fd: i32,
}

#[derive(Serialize, Debug)]
struct SocketInfo {
    inode: u64,
    #[serde(rename = "type")]
    type_: String,
    domain: FDSocketDomain,
    // NetEntry could be an unsupported type (eg: netlink, raw) or not initialized
    entry: Option<SocketEntry>,
}

#[derive(Serialize, Debug)]
enum FDTarget {
    // A file or device
    #[serde(rename = "path")]
    Path(PathBuf),
    // A socket type, with an inode
    #[serde(rename = "socket")]
    Socket(SocketInfo),
    // Network FD
    // NOTE: This is not the same as a tcp/udp socket. It's used by some
    // programs to manage the host's network itself.
    #[serde(rename = "net")]
    Net(u64),
    #[serde(rename = "pipe")]
    Pipe(PipeInfo),
    // A file descriptor that has no corresponding inode.
    #[serde(rename = "anon_inode")]
    AnonInode(String),
    // A memfd file descriptor with a name.
    #[serde(rename = "memfd")]
    MemFD(String),
    // Some other file descriptor type
    #[serde(rename = "other")]
    Other(String),

    // Other paths we're treating as if they were a file descriptor
    #[serde(rename = "cwd")]
    Cwd(PathBuf),
    #[serde(rename = "root")]
    Root(PathBuf),
    #[serde(rename = "exe")]
    Exe(PathBuf),
}

impl fmt::Display for FDTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            FDTarget::Path(path)
            | FDTarget::Cwd(path)
            | FDTarget::Exe(path)
            | FDTarget::Root(path) => path.display().to_string(),
            FDTarget::Socket(socket_info) => match &socket_info.entry {
                Some(e) => format!("{e}"),
                // Display an empty string for unsupported socket type
                None => {
                    if socket_info.type_.is_empty() {
                        String::new()
                    } else {
                        // Sometimes only the protocol is known
                        socket_info.type_.clone().to_uppercase()
                    }
                }
            },
            FDTarget::Pipe(p) => {
                let direction = if p.mode == 'r' { "<-" } else { "->" };
                // To save space when a pipe has lots of connected endpoints,
                // condense entries with the same proc name & fd, but different pids.
                // Eg: foo[789][1],httpd[123][5],httpd[456][5] => foo[789][1],httpd[123,456][5]
                let repeat_pids: HashMap<(String, i32), Vec<i32>> =
                    p.endpoints.iter().fold(HashMap::new(), |mut acc, x| {
                        acc.entry((x.name.clone(), x.fd)).or_default().push(x.pid);
                        acc
                    });
                let joined_endpoints = repeat_pids
                    .iter()
                    .sorted()
                    .map(|(k, v)| {
                        if v.len() == 1 && v[0] == p.self_pid {
                            return format!("[{}]", k.1);
                        }
                        let pids = v
                            .iter()
                            .sorted()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<String>>()
                            .join(",");
                        format!("{}[{}][{}]", k.0, pids, k.1)
                    })
                    .collect::<Vec<String>>()
                    .join(",");

                format!("pipe {direction} {joined_endpoints}")
            }
            FDTarget::Net(inode) => format!("net:[{inode}]"),
            FDTarget::AnonInode(inode_type) => inode_type.to_string(),
            FDTarget::MemFD(name) => name.to_string(),
            FDTarget::Other(_) => String::from("other"),
        };
        write!(f, "{msg}")
    }
}

// Combines process + fdinfo + fdtarget
#[derive(Serialize, Debug)]
// File descriptor entry
struct FDEntry {
    pid: i32,
    user: String,
    name: String,
    fd: Option<i32>,
    #[serde(rename = "type")]
    fd_type: String,
    target: FDTarget,
}

// Filter options for file descriptors
struct FDFilter {
    port: Option<u16>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    host: Option<String>,
    src_host: Option<String>,
    dst_host: Option<String>,
    type_: Option<FDType>,
    socket_domain: Option<FDSocketDomainFilter>,
    socket_type: Option<FDSocketTypeFilter>,
    socket_state: Option<String>,
}

fn host_or_ip_match(host_match: &str, ip_entry: &IpAddr, host_entry: &str) -> bool {
    ip_entry.to_string() == host_match || host_entry == host_match
}

// Implement file descriptor filtering logic
impl FDFilter {
    fn new(args: &Args) -> FDFilter {
        let mut type_ = args.type_;
        let mut socket_domain = args.socket_domain;
        // Filtering by port implies filtering by socket
        if args.port.is_some() || args.src_port.is_some() || args.dst_port.is_some() {
            type_ = Some(FDType::Socket);
            socket_domain = Some(FDSocketDomainFilter::Inet);
        }
        // Filtering by host implies filtering by socket
        if args.host.is_some() || args.src_host.is_some() || args.dst_host.is_some() {
            type_ = Some(FDType::Socket);
            socket_domain = Some(FDSocketDomainFilter::Inet);
        }
        // Filtering by socket type implies filtering by socket
        if args.socket_type.is_some() {
            type_ = Some(FDType::Socket);
        }
        // Filtering by socket state implies filtering by socket
        if args.socket_state.is_some() {
            type_ = Some(FDType::Socket);
        }
        if args.socket_domain.is_some() {
            type_ = Some(FDType::Socket);
        }
        FDFilter {
            port: args.port,
            src_port: args.src_port,
            dst_port: args.dst_port,
            host: args.host.clone(),
            src_host: args.src_host.clone(),
            dst_host: args.dst_host.clone(),
            type_,
            socket_type: args.socket_type,
            socket_domain,
            // socket state filtering is case insensitive
            socket_state: args.socket_state.clone().map(|s| s.to_uppercase()),
        }
    }

    // True if any file descriptor filter options are set
    fn has_filter_options(&self) -> bool {
        // Currently only socket filter options are supported, but
        // this could be extended to other types of filters in the future
        self.type_.is_some()
    }

    // True if any host or port filter options are set
    fn has_hostport_filter_options(&self) -> bool {
        self.port.is_some()
            || self.src_port.is_some()
            || self.dst_port.is_some()
            || self.host.is_some()
            || self.src_host.is_some()
            || self.dst_host.is_some()
    }

    // True if --host, --src-host, or --dst-host has a hostname filter
    fn has_hostname_filter(&self) -> bool {
        // Check if any hostname field is set and it's NOT an IP address
        self.host
            .as_ref()
            .is_some_and(|h| h.parse::<IpAddr>().is_err())
            || self
                .src_host
                .as_ref()
                .is_some_and(|h| h.parse::<IpAddr>().is_err())
            || self
                .dst_host
                .as_ref()
                .is_some_and(|h| h.parse::<IpAddr>().is_err())
    }

    // returns True if querying file descriptors is required
    // This is necessary for socket filters, but not for --type (cwd|exe|root)
    fn query_fds(&self) -> bool {
        // query file descriptors when there are no filter options or we're filtering by type = [socket, pipe, path]
        !self.has_filter_options()
            || self.type_ == Some(FDType::Socket)
            || self.type_ == Some(FDType::Pipe)
            || self.type_ == Some(FDType::Path)
    }

    fn query_pipe(&self) -> bool {
        // query Pipe when no filters OR --type pipe
        !self.has_filter_options() || self.type_ == Some(FDType::Pipe)
    }

    fn query_path(&self) -> bool {
        // query Path when no filters OR --type path
        !self.has_filter_options() || self.type_ == Some(FDType::Path)
    }

    fn query_cwd(&self) -> bool {
        // query exe when there are no filters OR a filter for --exe OR a filter for --path without --type
        !self.has_filter_options() || self.type_ == Some(FDType::Cwd) || self.type_.is_none()
    }

    fn query_root(&self) -> bool {
        // query exe when there are no filters OR a filter for --exe OR a filter for --path without --type
        !self.has_filter_options() || self.type_ == Some(FDType::Root) || self.type_.is_none()
    }

    fn query_exe(&self) -> bool {
        // query exe when there are no filters OR a filter for --exe OR a filter for --path without --type
        !self.has_filter_options() || self.type_ == Some(FDType::Exe) || self.type_.is_none()
    }

    fn query_socket(&self) -> bool {
        !self.has_filter_options() || self.type_ == Some(FDType::Socket)
    }

    fn match_socket_state(&self, state: &String) -> bool {
        // True if --socket-state is not specified or if it matches filter
        self.socket_state.as_ref().is_none_or(|s| *state == *s)
    }

    fn query_net_entry(&self, e: &mut NetConnEntry, socket_type: FDSocketTypeFilter) -> bool {
        // Only resolve hostnames when querying by hostname or if match succeeds
        // and --no-dns was not specified
        if self.has_hostname_filter() && e.dns_lookup {
            e.resolve_hostname();
        }
        let ret = !self.has_filter_options()
            || ((self.socket_type.is_none_or(|st| st == socket_type))
                && (self.socket_domain.is_none_or(|sd| {
                    sd == FDSocketDomainFilter::Inet
                        || (sd == FDSocketDomainFilter::Inet4 && e.ip_version == IpVersion::V4)
                        || (sd == FDSocketDomainFilter::Inet6 && e.ip_version == IpVersion::V6)
                }))
                && self.match_socket_state(&e.state)
                && self.match_port_entry(e.local_port, e.remote_port)
                && self.match_host_entry(e));
        if ret && e.dns_lookup {
            e.resolve_hostname();
        }
        ret
    }

    fn query_net_entry_other(&self, socket_protocol: FDSocketProtocol) -> bool {
        // Match unconnected sockets
        !self.has_hostport_filter_options()
            && self.socket_state.is_none()
            && self
                .socket_domain
                .is_none_or(|sd| sd == FDSocketDomainFilter::Inet)
            && self.socket_type.is_none_or(|st| {
                (st == FDSocketTypeFilter::Tcp && socket_protocol == FDSocketProtocol::Tcp)
                    || (st == FDSocketTypeFilter::Udp && socket_protocol == FDSocketProtocol::Udp)
            })
    }

    fn match_port_entry(&self, local_port: u16, remote_port: u16) -> bool {
        if (self
            .port
            .is_some_and(|port| local_port != port && remote_port != port))
            || (self.src_port.is_some_and(|port| local_port != port))
            || (self.dst_port.is_some_and(|port| remote_port != port))
        {
            return false;
        }
        true
    }

    fn match_host_entry(&self, e: &NetConnEntry) -> bool {
        if let Some(h) = &self.host {
            if !host_or_ip_match(h.as_str(), &e.local_ip, e.local_host.as_str())
                && !host_or_ip_match(h.as_str(), &e.remote_ip, e.remote_host.as_str())
            {
                return false;
            }
        }
        if let Some(h) = &self.src_host {
            if !host_or_ip_match(h.as_str(), &e.local_ip, e.local_host.as_str()) {
                return false;
            }
        }
        if let Some(h) = &self.dst_host {
            if !host_or_ip_match(h.as_str(), &e.remote_ip, e.remote_host.as_str()) {
                return false;
            }
        }
        true
    }

    fn query_unix_entry(&self, e: Option<&UnixSocketEntry>) -> bool {
        !self.has_filter_options()
            || (!self.has_hostport_filter_options()
                && (e.is_none_or(|f| self.match_socket_state(&f.state)))
                && self
                    .socket_domain
                    .is_none_or(|sd| sd == FDSocketDomainFilter::Unix)
                && self.socket_type.is_none_or(|st| {
                    e.is_none_or(|s| {
                        st == FDSocketTypeFilter::UnixDgram && s.socket_type == "dgram"
                            || st == FDSocketTypeFilter::UnixStream && s.socket_type == "stream"
                    })
                }))
    }

    fn query_other_socket(&self) -> bool {
        !self.has_hostport_filter_options()
            && self.socket_state.is_none()
            && self.socket_type.is_none()
            && self
                .socket_domain
                .is_none_or(|sd| sd == FDSocketDomainFilter::Other)
    }
}

fn get_fd_type(target: &FDTarget) -> String {
    match &target {
        FDTarget::Socket(_) => String::from("socket"),
        FDTarget::Cwd(_) => String::from("cwd"),
        FDTarget::Exe(_) => String::from("exe"),
        FDTarget::Root(_) => String::from("root"),
        FDTarget::Path(_) => String::from("path"),
        FDTarget::Pipe(..) => String::from("pipe"),
        FDTarget::Net(_) => String::from("net"),
        FDTarget::AnonInode(_) => String::from("anon_inode"),
        FDTarget::MemFD(_) => String::from("memfd"),
        FDTarget::Other(_) => String::from("other"),
    }
}

// File descriptor entry
impl FDEntry {
    fn new(process: &ProcessInfo, fd: Option<i32>, target: FDTarget) -> FDEntry {
        let fd_type = get_fd_type(&target);
        FDEntry {
            pid: process.pid,
            user: match get_user_by_uid(process.uid) {
                // Use lossy conversion because the results need to be exportable as json, which is UTF8
                Some(user) => user.name().to_string_lossy().to_string(),
                // If we can't find the user, just display the uid
                None => process.uid.to_string(),
            },
            name: process.comm.clone(),
            fd,
            fd_type,
            target,
        }
    }
    fn fd_type(&self) -> String {
        match &self.target {
            // for sockets, add the socket type inline
            FDTarget::Socket(s) => format!("socket[{}]", s.domain),
            _ => get_fd_type(&self.target),
        }
    }
}

// Apply file descriptor filters to a given process
#[allow(clippy::too_many_lines)]
fn process2fdtargets(
    process: &RefMulti<ProcessInfo>,
    net_maps: &NetMaps,
    pipe2pid: &HashMap<u64, Vec<PipeTarget>>,
    fd_filter: &FDFilter,
    dns_lookup: bool,
) -> Vec<FDEntry> {
    let mut fd_targets = Vec::new();
    // Query file descriptors only if necessary (not for --exe/--root/--cwd)
    if fd_filter.query_fds() {
        for fd in &process.fds {
            let fd_target: Option<FDTarget> = match &fd.target {
                process::FDTarget::Socket(inode) => {
                    if !fd_filter.query_socket() {
                        None
                    } else if let Some(e) = net_maps.tcp_map.get(inode) {
                        let mut net_entry = to_net_conn_entry(
                            e.local_address,
                            e.remote_address,
                            format!("{:?}", e.state).as_str(),
                            FDSocketProtocol::Tcp,
                            dns_lookup,
                        );
                        fd_filter
                            .query_net_entry(&mut net_entry, FDSocketTypeFilter::Tcp)
                            .then_some(FDTarget::Socket(SocketInfo {
                                inode: *inode,
                                type_: String::from("tcp"),
                                domain: FDSocketDomain::Inet,
                                entry: Some(SocketEntry::Inet(net_entry)),
                            }))
                    } else if let Some(e) = net_maps.udp_map.get(inode) {
                        let mut net_entry = to_net_conn_entry(
                            e.local_address,
                            e.remote_address,
                            format!("{:?}", e.state).as_str(),
                            FDSocketProtocol::Udp,
                            dns_lookup,
                        );
                        fd_filter
                            .query_net_entry(&mut net_entry, FDSocketTypeFilter::Udp)
                            .then_some(FDTarget::Socket(SocketInfo {
                                inode: *inode,
                                type_: String::from("udp"),
                                domain: FDSocketDomain::Inet,
                                entry: Some(SocketEntry::Inet(net_entry)),
                            }))
                    } else if let Some(unix_socket_entry) = net_maps.unix_map.get(inode) {
                        fd_filter
                            .query_unix_entry(Some(unix_socket_entry))
                            .then_some(FDTarget::Socket(SocketInfo {
                                inode: *inode,
                                type_: unix_socket_entry.socket_type.to_string(),
                                domain: FDSocketDomain::Unix,
                                entry: Some(SocketEntry::Unix(unix_socket_entry.clone())),
                            }))
                    } else if let Some(socket_protocol) =
                        get_socket_protocol_from_fd(process.pid, fd.fd)
                    {
                        // Unconnected socket
                        fd_filter.query_net_entry_other(socket_protocol).then_some(
                            FDTarget::Socket(SocketInfo {
                                inode: *inode,
                                type_: socket_protocol.to_string(),
                                domain: FDSocketDomain::Inet,
                                entry: None,
                            }),
                        )
                    } else {
                        // Another socket, but we don't know its type
                        fd_filter
                            .query_other_socket()
                            .then_some(FDTarget::Socket(SocketInfo {
                                inode: *inode,
                                type_: String::from("other"),
                                domain: FDSocketDomain::Other,
                                entry: None,
                            }))
                    }
                }
                process::FDTarget::Path(path_buf) => fd_filter
                    .query_path()
                    .then_some(FDTarget::Path(path_buf.clone())),
                process::FDTarget::Pipe(inode) => fd_filter.query_pipe().then(|| {
                    let mode = if fd.mode() & READ == READ { 'r' } else { 'w' };
                    FDTarget::Pipe(PipeInfo {
                        inode: *inode,
                        mode,
                        endpoints: lookup_pipe2pid(*inode, process.pid, fd.fd, mode, pipe2pid),
                        self_pid: process.pid,
                    })
                }),
                // Only display Net/AnonInode/MemFD FDs if no other filters are specified
                process::FDTarget::Net(inode) => fd_filter
                    .has_filter_options()
                    .not()
                    .then_some(FDTarget::Net(*inode)),
                process::FDTarget::AnonInode(inode) => fd_filter
                    .has_filter_options()
                    .not()
                    .then_some(FDTarget::AnonInode(inode.to_string())),
                process::FDTarget::MemFD(inode) => fd_filter
                    .has_filter_options()
                    .not()
                    .then_some(FDTarget::MemFD(inode.to_string())),
                process::FDTarget::Other(..) => fd_filter
                    .has_filter_options()
                    .not()
                    .then_some(FDTarget::Other("other".to_string())),
            };
            if let Some(fd_target) = fd_target {
                fd_targets.push(FDEntry::new(process, Some(fd.fd), fd_target));
            }
        }
    }
    if fd_filter.query_exe() {
        if let Some(path) = &process.exe {
            let fd_target = FDTarget::Exe(path.clone());
            fd_targets.push(FDEntry::new(process, None, fd_target));
        }
    }
    if fd_filter.query_cwd() {
        if let Some(path) = &process.cwd {
            let fd_target = FDTarget::Cwd(path.clone());
            fd_targets.push(FDEntry::new(process, None, fd_target));
        }
    }
    if fd_filter.query_root() {
        if let Some(path) = &process.root {
            let fd_target = FDTarget::Root(path.clone());
            fd_targets.push(FDEntry::new(process, None, fd_target));
        }
    }
    fd_targets
}

// Unconnected sockets do not appear in /proc/net/{tcp,udp} but we can get their
// type by reading the system.sockprotoname attribute on the file descriptor filename
fn get_socket_protocol_from_fd(pid: i32, fd: i32) -> Option<FDSocketProtocol> {
    let path = format!("/proc/{pid}/fd/{fd}");
    let xprop = xattr::get_deref(path, "system.sockprotoname").ok()??;
    let res = String::from_utf8(xprop)
        .expect("Unexpected data reading system.sockprotoname") // Should never happen as this is an OS generated string
        .trim_end_matches('\0')
        .to_lowercase();
    match res.as_str() {
        "tcp" => Some(FDSocketProtocol::Tcp),
        "udp" => Some(FDSocketProtocol::Udp),
        _ => None,
    }
}

// get a mapping of TCP, UDP, and Unix maps
fn get_net_maps() -> Result<NetMaps> {
    let tcp_h = thread::spawn(|| procfs::net::tcp().wrap_err("Error reading TCP map"));
    let udp_h = thread::spawn(|| procfs::net::udp().wrap_err("Error reading TCP map"));
    let unix_h = thread::spawn(|| procfs::net::unix().wrap_err("Error reading Unix map"));
    let tcp_h_v6 = thread::spawn(|| match procfs::net::tcp6() {
        Err(err) => match err {
            // NotFound means IPv6 is not enabled - return empty array
            procfs::ProcError::NotFound(_) => Ok(vec![]),
            _ => Err(err).wrap_err("Error reading TCP6 map"),
        },
        Ok(res) => Ok(res),
    });
    let udp_h_v6 = thread::spawn(|| match procfs::net::udp6() {
        Err(err) => match err {
            // NotFound means IPv6 is not enabled - return empty array
            procfs::ProcError::NotFound(_) => Ok(vec![]),
            _ => Err(err).wrap_err("Error reading UDP6 map"),
        },
        Ok(res) => Ok(res),
    });

    let tcp = tcp_h
        .join()
        .expect("Error joining thread collecting TCP map")?;
    let tcp6 = tcp_h_v6
        .join()
        .expect("Error joining thread collecting TCP6 map")?;
    let mut tcp_map: HashMap<u64, net::TcpNetEntry> = HashMap::new();
    for entry in tcp.into_iter().chain(tcp6) {
        tcp_map.insert(entry.inode, entry);
    }
    let udp = udp_h
        .join()
        .expect("Error joining thread collecting UDP map")?;
    let udp6 = udp_h_v6
        .join()
        .expect("Error joining thread collecting UDP6 map")?;
    let mut udp_map: HashMap<u64, net::UdpNetEntry> = HashMap::new();
    for entry in udp.into_iter().chain(udp6) {
        udp_map.insert(entry.inode, entry);
    }

    let unix = unix_h
        .join()
        .expect("Error joining thread collecting Unix map")?;
    let mut unix_map: HashMap<u64, UnixSocketEntry> = HashMap::new();
    for entry in unix {
        unix_map.insert(
            entry.inode,
            UnixSocketEntry {
                socket_type: SOCKET_TYPES[entry.socket_type as usize].to_string(),
                path: entry.path.map(|e| e.display().to_string()),
                state: format!("{:?}", entry.state),
                peer: None, // populated later in update_unix_map_with_peer
            },
        );
    }
    // TODO: Few other types are supported, but we don't care about them for now
    Ok(NetMaps {
        tcp_map,
        udp_map,
        unix_map,
    })
}

fn lookup_pipe2pid(
    inode: u64,
    pid: i32,
    fd: i32,
    mode: char,
    pipe2pid: &HashMap<u64, Vec<PipeTarget>>,
) -> Vec<PipeTarget> {
    // Look up the connected processes for this pipe
    let empty: Vec<PipeTarget> = Vec::new();
    let mut targets = pipe2pid.get(&inode).unwrap_or(&empty).clone();
    // exclude own pid/fd from result
    targets.retain(|x| !(x.pid == pid && x.fd == fd));
    // exclude fds with the same mode
    targets.retain(|x| x.mode != mode);
    targets
}

fn get_pipe2pid(all_procs: &Arc<DashSet<ProcessInfo>>) -> HashMap<u64, Vec<PipeTarget>> {
    let mut pipe2pid: HashMap<u64, Vec<PipeTarget>> = HashMap::new();
    // Populate the mapping of all pipe inodes to pid/fd

    for process in all_procs.iter() {
        for fd in &process.fds {
            if let process::FDTarget::Pipe(inode) = fd.target {
                let remote_pids = pipe2pid.entry(inode).or_default();
                remote_pids.push(PipeTarget {
                    pid: process.pid,
                    name: process.comm.clone(),
                    fd: fd.fd,
                    mode: if fd.mode() & READ == READ { 'r' } else { 'w' },
                });
            }
        }
    }
    pipe2pid
}

// Get the mapping of all unix socket inodes to the peer pid/fd
fn update_unix_map_with_peer(
    all_procs: &Arc<DashSet<ProcessInfo>>,
    unix_map: &mut HashMap<u64, UnixSocketEntry>,
) -> Result<()> {
    let mut socket2fd: HashMap<u64, Vec<FDEndpoint>> = HashMap::new();
    // First populate a mapping of all socket inodes to Vec<FDEndpoint> (pid/fd)
    for process in all_procs.iter() {
        for fd in &process.fds {
            if let process::FDTarget::Socket(inode) = fd.target {
                socket2fd.entry(inode).or_default().push(FDEndpoint {
                    pid: process.pid,
                    name: process.comm.clone(),
                    fd: fd.fd,
                });
            }
        }
    }
    // This code is based on
    // https://github.com/rust-netlink/netlink-packet-sock-diag/blob/main/examples/dump_ipv4.rs
    let socket = Socket::new(NETLINK_SOCK_DIAG)?;
    socket.connect(&NlSocketAddr::new(0, 0))?;

    let mut nl_hdr = NetlinkHeader::default();
    nl_hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut packet = NetlinkMessage::new(
        nl_hdr,
        SockDiagMessage::UnixRequest(UnixRequest {
            state_flags: StateFlags::all(),
            inode: 0,
            show_flags: ShowFlags::PEER | ShowFlags::NAME,
            cookie: [0; 8],
        })
        .into(),
    );

    packet.finalize();

    let mut buf = vec![0; packet.header.length as usize];

    // Before calling serialize, it is important to check that the buffer in
    // which we're emitting is big enough for the packet, other
    // `serialize()` panics.
    assert_eq!(buf.len(), packet.buffer_len());

    packet.serialize(&mut buf[..]);

    socket.send(&buf[..], 0)?;

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    'outer: while let Ok(size) = socket.recv(&mut &mut receive_buffer[..], 0) {
        loop {
            let bytes = &receive_buffer[offset..];
            let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes)?;

            match rx_packet.payload {
                NetlinkPayload::Noop => {}
                NetlinkPayload::InnerMessage(SockDiagMessage::UnixResponse(response)) => {
                    let inode = response.header.inode;
                    let peer = response.peer().unwrap_or_default();
                    // Replace null character with @, as shown in /proc/net/unix
                    let path = response.name().cloned().map(|p| p.replace('\0', "@"));

                    // populate the peer inode to this socket map
                    if let Some(src_sockets) = socket2fd.get(&inode.into()) {
                        let mut src_sockets = src_sockets.clone();
                        // Sort by pid, then fd
                        src_sockets.sort_by(|a, b| (a.pid, a.fd).cmp(&(b.pid, b.fd)));
                        if let Some(net_entry) = unix_map.get_mut(&peer.into()) {
                            net_entry.peer = Some(SocketEndpoint {
                                inode: inode.into(),
                                path: path.clone(),
                                endpoints: src_sockets,
                            });
                        }
                    }
                    if let Some(net_entry) = unix_map.get_mut(&inode.into()) {
                        // Rewrite connection state to be more like the output of `ss`
                        if response.header.state == sock_diag_constants::TCP_ESTABLISHED {
                            net_entry.state = "ESTABLISHED".to_string();
                        } else if response.header.state == sock_diag_constants::TCP_LISTEN {
                            net_entry.state = "LISTEN".to_string();
                        }
                        // other states are not possible because the sock_diag protocol does not support them
                    }
                }
                NetlinkPayload::Error(err) => {
                    bail!("ERROR receiving data from diagnostic socket: {err}");
                }
                _ => break 'outer,
            }

            offset += rx_packet.header.length as usize;
            if offset == size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
    Ok(())
}

fn clear_environment() {
    for (key, _) in env::vars() {
        env::remove_var(key);
    }
}

struct ProcessInfo {
    pid: i32,
    uid: u32,
    comm: String,
    fds: Vec<FDInfo>,
    // The exe/cwd/root fields are only populated if displaying them is necessary
    exe: Option<PathBuf>,
    cwd: Option<PathBuf>,
    root: Option<PathBuf>,
    included_by_filters: bool,
}

// Implement Eq, PartialEq, and Hash for ProcessInfo to be used in a DashSet
impl Eq for ProcessInfo {}

impl PartialEq for ProcessInfo {
    fn eq(&self, other: &Self) -> bool {
        // It's safe to compare Processes only by pid. pid reuse is not an issue in the context of procfd
        // since we're fetching all pids once, then processing each pid atomically.
        self.pid == other.pid
    }
}

impl std::hash::Hash for ProcessInfo {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // It's safe to compare Processes only by pid. pid reuse is not an issue in the context of procfd
        // since we're fetching all pids once, then processing each pid atomically.
        self.pid.hash(state);
    }
}

fn get_all_processes(args: &Args, fd_filter: &FDFilter) -> Arc<DashSet<ProcessInfo>> {
    let all_procs: Arc<DashSet<ProcessInfo>> = Arc::new(DashSet::new());
    let query_fds = fd_filter.query_fds();

    // Collect all the process pids first
    // We don't hold on to the Process object because it keeps an open file descriptor
    // to /proc/<pid> so we might run out of file descriptors.
    let all_pids: Vec<i32> = procfs::process::all_processes()
        .unwrap()
        .filter_map(Result::ok)
        .map(|p| p.pid())
        .collect();
    // Now collect the process info for each pid in parallel
    all_pids.par_iter().for_each(|pid| {
        let Ok(proc) = procfs::process::Process::new(*pid) else {
            return; // process vanished
        };
        let Ok(stat) = proc.stat() else {
            return; // process vanished
        };
        let Ok(uid) = proc.uid() else {
            return; // process vanished
        };
        let mut process_info = ProcessInfo {
            pid: proc.pid(),
            uid,
            comm: stat.comm,
            fds: Vec::new(),
            exe: None,
            cwd: None,
            root: None,
            included_by_filters: true,
        };
        process_info.included_by_filters = args.filter_process(&process_info);

        if process_info.included_by_filters {
            // populate exe, cwd, root only if necessary
            if fd_filter.query_exe() {
                process_info.exe = proc.exe().ok();
            }
            if fd_filter.query_cwd() {
                process_info.cwd = proc.cwd().ok();
            }
            if fd_filter.query_root() {
                process_info.root = proc.root().ok();
            }
        }
        if query_fds {
            let Ok(fds) = proc.fd() else {
                return; // process vanished
            };
            process_info.fds = fds.filter_map(Result::ok).collect();
        }

        all_procs.insert(process_info);
    });
    all_procs
}

fn main() -> Result<()> {
    // As a general security practice, clear the environment in case the command is run privileged
    clear_environment();

    let args = Args::parse();

    // query all processes and initialize filtering
    let fd_filter = FDFilter::new(&args);

    let all_procs = get_all_processes(&args, &fd_filter);

    // collect mapping of inode to tcp/udp/unix entry
    let mut net_maps = get_net_maps().wrap_err("Error collecting network maps")?;

    // update unix map with peer info
    if fd_filter.query_fds() && fd_filter.query_unix_entry(None) {
        update_unix_map_with_peer(&all_procs, &mut net_maps.unix_map)
            .wrap_err("Error collecting socket peer data")?;
    }

    // collect pipe mappings only if necessary
    let pipe2pid = if fd_filter.query_fds() && fd_filter.query_pipe() {
        get_pipe2pid(&all_procs)
    } else {
        HashMap::new()
    };

    // populate a list of FDEntry
    let mut all_fds = Vec::new();

    // Render table
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(row!("PID", "User", "Name", "Type", "FD", "Target"));

    for process in all_procs.iter() {
        if !process.included_by_filters {
            // skip this process if it doesn't match the process filter
            continue;
        }
        // extract matching fd entries for this process
        let fd_entries =
            process2fdtargets(&process, &net_maps, &pipe2pid, &fd_filter, !args.no_dns);

        for fd_entry in fd_entries {
            let fd_str = match fd_entry.fd {
                Some(fd) => format!("{fd}"),
                None => String::new(),
            };
            table.add_row(Row::new(vec![
                Cell::new(format!("{}", fd_entry.pid).as_str()),
                Cell::new(fd_entry.user.as_str()),
                Cell::new(fd_entry.name.as_str()),
                Cell::new(fd_entry.fd_type().as_str()),
                Cell::new(fd_str.as_str()),
                Cell::new(format!("{}", fd_entry.target).as_str()),
            ]));
            all_fds.push(fd_entry);
        }
    }
    if args.json {
        let serialized = serde_json::to_string(&all_fds).wrap_err("Error serializing json")?;
        println!("{serialized}");
    } else if !all_fds.is_empty() {
        table.printstd();
    }
    Ok(())
}
