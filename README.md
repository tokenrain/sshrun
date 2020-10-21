# sshrun, scprun, rsyncrun

sshrun, scprun, and rsyncrun are command line tools that provide
concurrent command execution and file/directory copy to a set of remote
hosts.

These tools emulate the fantastic parallel-* set from
[code.google.com](https://code.google.com/archive/p/parallel-ssh)

They were written for the following reasons:

* To allow the author to experiment with golang go routines and
channels.

* To modify small behaviours of the original tools to better meet the
needs of the author.

## Differences from parallel-ssh

* Status output shows the time that each run spent on host execution
rather than the time spent since the overall run started.

* Head and Tail options allow for a defined amount of stdout to be
displayed on the same line as host execution status.

* These tools do not support askpass. ssh-agent or some other form
of password less connections need to be in effect.

## Documentation

See sshrun.1.ronn or `man sshrun`

## Usage

```
Usage:
  sshrun   [OPTIONS] cmd...
  scprun   [OPTIONS] src dir
  rsyncrun [OPTIONS] src dir

Application Options:
  -h, --hosts_file= file containing host targets (delim = ' '|\t|\n)
  -H, --hosts_list= string containing host targets (delim = ,|' ')
  -p, --parallel=   number of concurrent runs to perform (default = 16)
  -t, --timeout=    timeout (seconds) of each run (default = 15)
  -o, --opts=       additional options for ssh|scp|rsync !(opt=val opt=val ...)
  -s, --ssh_opts=   additional options for ssh (opt=val opt=val ...)
  -a, --archive     use archive mode for rsync runs
  -y, --identity=   identity file for ssh|scp|rsync
  -u, --user=       user on remote for ssh|scp|rsync
  -d, --dir=        output directory for stdout/stderr files
  -i, --inline      display stdout & stderr inline
      --head=       display first X number of stdout bytes inline
      --tail=       display last X number of stdout bytes inline
      --version     display version and exit
      --no-status   do not print status of each run to stdout
      --debug       print debug output

      targets can be formated as host | user@host | host:port | user@host:port

Help Options:
      --help        Show this help message
```

## Examples

```
sshrun -h /tmp/hosts.txt -p 32 -t 30 --head=80 uptime

sshrun -H "host1 host2 host3" --opts="-A -x" --ssh_opts="BatchMode=yes ForwardX11=no" -t 30 'command1 && command2'

scprun -h /tmp/hosts.txt --opts="-p" /tmp/file.txt /tmp/

scprun -h /tmp/hosts.txt --opts="-p -r" /tmp/dir1 /tmp/

rsyncrun -H "host1 host2 host3" -a --opts"-H" --ssh_opts="BatchMode=yes" /var/tmp/dir1 /var/tmp/
```

## Building

Building the binary requires only go to be installed.

Building os packages requies go, ruby, fpm (ruby gem) and ronn (ruby
gem) to be installed.

`make all` to build binary.

`make packages` to build os packages.
