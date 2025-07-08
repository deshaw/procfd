# procfd

## Introduction
procfd is a Linux tool to query open file descriptors for processes. It is a rust replacement for the `lsof` command. Compared to `lsof`, `procfd` features:

* Safe against blocking operations
* Easy to use command-line options
* Simple to use filters
* Very fast
* Can export data as json

## Examples

### Filter by PID

```bash
$ procfd --pid 3964924
PID      | User     | Name | Type         | FD | Target
---------+----------+------+--------------+----+-------------------------------------------------------------------------
 3964924 | maverick | sshd | file         | 0  | /dev/null
 3964924 | maverick | sshd | file         | 1  | /dev/null
 3964924 | maverick | sshd | file         | 2  | /dev/null
 3964924 | maverick | sshd | socket[inet] | 3  | TCP: localhost:60168 -> localhost:39629 (ESTABLISHED)
 3964924 | maverick | sshd | socket[inet] | 4  | TCP: my-host.com:22 -> remote-host.com:63706 (ESTABLISHED)
 3964924 | maverick | sshd | file         | 5  | /etc/krb5/db/data.mdb
 3964924 | maverick | sshd | socket[unix] | 6  | stream (ESTABLISHED)
 3964924 | maverick | sshd | socket[unix] | 7  | stream -> sshd[3964921] (ESTABLISHED)
 3964924 | maverick | sshd | file         | 8  | /etc/krb5/db/data.mdb
 3964924 | maverick | sshd | file         | 9  | /run/systemd/sessions/157280.ref
 3964924 | maverick | sshd | pipe         | 10 | pipe <- [11]
 3964924 | maverick | sshd | pipe         | 11 | pipe -> [10]
 3964924 | maverick | sshd | socket[inet] | 12 | TCP: localhost:60176 -> localhost:39629 (ESTABLISHED)
 3964924 | maverick | sshd | pipe         | 15 | pipe <- sleep[2813702][1],bash[3964926][1]
 3964924 | maverick | sshd | pipe         | 17 | pipe <- sleep[2813702][2],bash[3964926][2]
 3964924 | maverick | sshd | exe          |    | /usr/sbin/sshd
 3964924 | maverick | sshd | cwd          |    | /
 3964924 | maverick | sshd | root         |    | /
```

### Filtering examples

* `procfd --type {socket,cwd,root,exe,path,pipe}` - Filter by socket type
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

## Comparison to lsof and lsfd

* `lsof` is the original cross-platform command to list open file handles
* `lsfd` is a Linux-only rewrite of `lsof` by one of the main contributors to `lsof` which addresses many usability issues with `lsof`

Below is an incomplete comparison of these tools:

| Feature                          | procfd         | lsof                   | lsfd           |
| -------------------------------- | -------------- | ---------------------- | -------------- |
| Language                         | rust           | C                      | C              |
| Platform support                 | Linux only     | Cross-platform         | Linux only     |
| Speed                            | Very fast      | Variable [^1]          | Variable       |
| JSON output                      | Yes            | No                     | Yes            |
| Avoid blocking operations        | Yes            | Partial [^2]           | No             |
| Display endpoint of unix sockets | Yes            | Very slow with -E flag | No             |
| Display endpoint of pipes        | Yes            | Very slow with -E flag | Yes            |
| Usability                        | Very easy      | Complicated            | Medium         |
| Show memory maps                 | No[^3]         | Yes                    | Yes            |
| Filter by expression             | No             | No                     | Yes            |
| DNS Lookups                      | Yes            | Yes                    | No             |
| Show mount points                | No             | Yes                    | Yes            |
| IPv6 support                     | Yes            | Yes                    | Yes            |
| Filter by path                   | No[^4]         | Yes                    | Yes            |
| Filter by command                | Yes with regex | Yes exact match        | Yes with regex |
| Filter by src/dst host/port      | Yes            | No                     | Yes            |

### Notes

[^1]: Fast with local disks, but can be slow with lots of mounted network filesystems
[^2]: `lsof -b` flag avoids blocking calls, but also fails to display any socket information
[^3]: Not currently implemented but PRs welcome!
[^4]: Not currently implemented, but can use grep to filter output of `procfd --type path`

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
