# procfd

## Introduction
procfd is a Linux tool to query open file descriptors for processes. It is a rust replacement for the `lsof` command. Compared to `lsof`, `procfd`:

* Is very fast
* Is safe against blocking operations and never hangs
* Has easy to use command-line options and filters
* Shows endpoints of pipes and unix sockets by default
* Can export data as json

## Examples

### Filter by PID

```bash
$ procfd --pid 710156
 PID    | User     | Name | Type         | FD | Mode | Target
--------+----------+------+--------------+----+------+---------------------------------------------------------------------------------
 710156 | maverick | sshd | path         | 0  | rw   | /dev/null
 710156 | maverick | sshd | path         | 1  | rw   | /dev/null
 710156 | maverick | sshd | path         | 2  | rw   | /dev/null
 710156 | maverick | sshd | path         | 3  | rw   | /dev/ptmx
 710156 | maverick | sshd | socket[inet] | 4  | rw   | TCP: my-host.com:22 -> remote-host.com:63706 (ESTABLISHED)
 710156 | maverick | sshd | path         | 5  | r    | /etc/krb5/db/data.mdb
 710156 | maverick | sshd | socket[unix] | 6  | rw   | stream (ESTABLISHED)
 710156 | maverick | sshd | socket[unix] | 7  | rw   | stream -> sshd[710152][9] (ESTABLISHED)
 710156 | maverick | sshd | path         | 8  | w    | /run/systemd/sessions/349.ref
 710156 | maverick | sshd | pipe         | 9  | r    | pipe -> [10]
 710156 | maverick | sshd | pipe         | 10 | w    | pipe -> [9]
 710156 | maverick | sshd | path         | 14 | rw   | /dev/ptmx
 710156 | maverick | sshd | path         | 15 | rw   | /dev/ptmx
 710156 | maverick | sshd | pipe         | 16 | r    | pipe -> sleep[2813702][1],bash[3964926][1]
 710156 | maverick | sshd | pipe         | 17 | r    | pipe -> sleep[2813702][2],bash[3964926][2]
 710156 | maverick | sshd | exe          |    |      | /usr/sbin/sshd
 710156 | maverick | sshd | cwd          |    |      | /
 710156 | maverick | sshd | root         |    |      | /
 710156 | maverick | sshd | mmap         |    |      | /usr/lib64/ld-2.28.so
 710156 | maverick | sshd | mmap         |    |      | /usr/lib64/libaudit.so.1.0.0
 710156 | maverick | sshd | mmap         |    |      | /usr/lib64/libblkid.so.1.1.0
 710156 | maverick | sshd | mmap         |    |      | /usr/lib64/libc-2.28.so
```

### Filtering examples

* `procfd --type {socket,cwd,root,exe,path,pipe,mmap}` - Filter by socket type
* `procfd --socket-domain {unix,inet,inet4,inet6,other}` - Filter sockets by domain
* `procfd --socket-type {tcp,udp,unix-stream,unix-dgram}` - Filter by socket type
* `procfd --socket-state {listen,established,close}` - Filter by socket state
* `procfd --src-host 10.77.10.3 --src-port 1044 --dst-host google.com --dst-port 443` - Filter by source AND destination host/port
* `procfd --port 443` - Filter by source OR destination port
* `procfd --cmd ssh` - Filter by command (exact match)
* `procfd --cmd /ssh/` - Filter by command (regex match)
* `procfd --user maverick` - Filter by username
* `procfd --pid 3964924` - Filter by process ID

### Other options

* `procfd --no-dns` - Disable DNS lookups
* `procfd --json` - Render results as JSON
* `procfd --pid-only` - Only show PIDs

## Installation

procfd is not yet available as a distro package, but you can install it using Cargo or download it from the Releases page

### Cargo

![Crates.io](https://img.shields.io/crates/v/procfd?link=https%3A%2F%2Fcrates.io%2Fcrates%2Fprocfd)

procfd can be installed directly from crates.io with:
```
cargo install procfd
```
Cargo will build the `procfd` binary and place it in your `CARGO_INSTALL_ROOT`.
For more details on installation location see [the cargo
book](https://doc.rust-lang.org/cargo/commands/cargo-install.html#description).

### Nix

[![nixpkgs unstable package](https://repology.org/badge/version-for-repo/nix_unstable/procfd.svg)](https://repology.org/project/procfd/versions)

```
nix-env -iA nixpkgs.procfd
```

### Manual

Download the binary on the [releases](https://github.com/deshaw/procfd/releases) page and put them in your $PATH. Or run the shell command:

```shell
wget -c https://github.com/deshaw/procfd/releases/latest/download/procfd-x86_64-unknown-linux-gnu.tar.gz -O - | tar xz
```

## Comparison to lsof and lsfd

* `lsof` is the original cross-platform command to list open file handles
* `lsfd` is a Linux-only rewrite of `lsof` by one of the main contributors to `lsof` which addresses many usability issues with `lsof`

Below is an incomplete (and biased) comparison of these tools:

| Feature                          | procfd         | lsof                   | lsfd           |
| -------------------------------- | -------------- | ---------------------- | -------------- |
| Language                         | rust           | C                      | C              |
| Platform support                 | Linux only     | Cross-platform         | Linux only     |
| Speed                            | Very fast      | Variable [^1]          | Variable       |
| JSON output                      | Yes            | No                     | Yes            |
| Avoids blocking operations       | Yes            | Partial [^2]           | No             |
| Display endpoint of unix sockets | Yes            | Partial [^3]           | Partial        |
| Display endpoint of pipes        | Yes            | Yes (with lsof -E)     | Yes            |
| Usability                        | Easy           | Complicated            | Medium         |
| Filter by expression             | No             | Partial                | Yes            |
| DNS Lookups                      | Yes            | Yes                    | No             |
| Show mount points                | No             | Yes                    | Yes            |
| Protocol support                 | Partial[^5]    | Full                   | Full           |
| Filter by path                   | No[^4]         | Yes                    | Yes            |
| Filter by command                | Yes with regex | Yes exact match        | Yes with regex |
| Filter by src/dst host/port      | Yes            | No                     | Yes            |

## History

procfd was contributed back to the community by the [D. E. Shaw group](https://www.deshaw.com/).

<p align="center">
    <a href="https://www.deshaw.com">
       <img src="https://www.deshaw.com/assets/logos/blue_logo_417x125.png" alt="D. E. Shaw Logo" height="75" >
    </a>
</p>

## License

This project is released under a [BSD-3-Clause license](https://github.com/deshaw/procfd/blob/master/LICENSE.txt).

We love contributions! Before you can contribute, please sign and submit this [Contributor License Agreement (CLA)](https://www.deshaw.com/oss/cla).
This CLA is in place to protect all users of this project.

### Notes

[^1]: Fast with local disks, but can be very slow with lots of mounted network filesystems
[^2]: `lsof -b` avoids blocking calls, but also fails to display any socket information
[^3]: `lsfd` and `lsof +E` display limited information about the socket endpoint including the command, socket number, and fd number, but not the socket endpoint path. `lsfd` may miss some endpoints if process filters are applied
[^4]: Not currently implemented, but can use grep to filter output of `procfd --type path`
[^5]: List of unsupported protocols is listed in [#12](https://github.com/deshaw/procfd/issues/12)