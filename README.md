# ansj - a network service jailer

## WARNING

Do not trust my code, it's probably not secure. Do not use this unless you've extensively reviewed the code and understand what it does. This is a personal project and I am not responsible for any damage caused by it. (In fact, while developing this, I accidentally deleted half of my file system). I am neither a security expert, nor an experienced C programmer. This is a learning project to better understand modern sandboxing techniques.

## About

Lightweight(?) network service jailer.
Intended for hosting MULTIPLE pwn ctf challenges on a SINGLE port.
For more information including the required setup and config format, see [setup](#setup).

## Usage

```txt
  nsj [options]
```

## Options

```txt
  -h,  --help                      This help text
  -a,  --addr <addr>               IP address to bind to (default :: and 0.0.0.0).
  -p,  --port <port>               TCP port to bind to (default 1024).
  -s,  --single                    Serve a single challenge only. the first line of the config file is used without prompting for the key.
  -l,  --log <path>                Log all user input and append it to a file named <path>. if <path> is '-' stdout is used.
  -nt, --no-time                   Don't tell the user how much time their instance has.
  -ni, --no-stdin                  Don't use the socket as stdin.
  -no, --no-stdout                 Don't use the socket as stdout.
  -ne, --no-stderr                 Don't use the socket as stderr. useful for debugging.
  -lu, --limit-cpu-usage <lim>     Maximum cpu usage per connection in percent (default unchanged).
  -lm, --limit-memory <lim>        Limit the amount of memory in bytes (default unchanged).
  -lp, --limit-processes <lim>     Limit the number of processes (default unchanged).
  -lc, --limit-connections <lim>   Limit the number of concurrent connections per ip (default 1).
  -lf, --limit-tmpfs <lim>         Limit the size of tmpfs in bytes (default 262144 aka 256KiB).
```

## Setup

### config

The config file is used to set up the files inside the jail (flag, binaries) as well as the time after which the jail is destroyed. It also holds the key associated with the challenge. Users will be prompted for this key and can thus access multiple challenges on the same port.

Every line in the config must follow the format:

```txt
:key:dirname_in_challenges:file_in_dir_to_exec:timeout_in_seconds:challenge_dir_path_in_jail:list/nolist:suid/nosuid:copy/nocopy:
```

| Field | Description |
| --- | --- |
| **key** | The unique key associated with the challenge. CANNOT BE 'help' OR CONTAIN ':' OR ' '. |
| **dirname_in_challenges** | The name of the directory in ./challenges that contains the challenge files. |
| **file_in_dir_to_exec** | The name of the file in dirname_in_challenges that will be executed in the jail. |
| **timeout_in_seconds** | The time in seconds after which the jail will be destroyed. |
| **challenge_dir_path_in_jail** | The path to the directory in the jail where the challenge files will be accessible. Must be absolute. Cannot use /old, /home, /proc, /bin, /lib, /lib64, /usr, /etc, /var, /dev, /sbin. |
| **list/nolist** | If this value is 'list', the key will be listed when the user types 'help'. |
| **suid/nosuid** | If this value is 'suid', the file_in_dir_to_exec will be made suid root. If copy is not set, this will make the file suid root outside of the jail too. YOU PROBABLY DON'T WANT THIS. USE copy FOR SUID CHALLENGES. |
| **copy/nocopy** | If this value is 'copy', the challenge directory will be copied into the jail instead of bind-mounted. This may be slower for challenges with many files. |

```txt
DO NOT LEAVE ANY VALUES EMPTY. TO OPT OUT OF list OR suid OR copy, USE 'nolist' OR 'nosuid' OR 'nocopy' OR LITERALLY ANY OTHER STRING. DO NOT DO THIS: 
:key:dirname_in_challenges:file_in_dir_to_exec::challenge_dir_path_in_jail::::
```

## Examples

This repo comes with three common use case examples. The [bash](/challenges/default/) challenge may be kept as a way for users to explore the file system and get a feel for the environment. It also aims to show how to correctly use a setup/init binary to customize the jail. The [bof](/challenges/unpriv_bof_example/) challenge is a classic buffer overflow that never executes any code as root. The [python](/challenges/python_example/) challenge is to demonstrate how to get python code running, but note that there might be complications with python due to the minimal file system of the jail. The [rootshell](/challenges/rootshell_example/) challenge gives you a root shell inside the jail to test it's limitations and security. For more information on the examples refer to the source code directly.

## How it works

To use **namespaces** and **capabilities**, the program must be run as root (or rather requires certain capabilities that usually only root has). The program will also make sure a `ctf` user exists. If it doesn't, it will be created with the password `ctf`.

The ynetd based server keeps accepting connections and applies ressource limits. Each connection will then prompt for a key and time out after 5 seconds if no key is entered. The config line containing the key (if it exists) will be parsed.

The jail is created in a new mount namespace that doesn't share the pid and network namespaces with the host. This means the jailed process can't access the host's network or processes. The new pid namespace along with a fresh /proc mount is important as it prohibits a sandbox escape via setns to the host's pid namespace.

To isolate the filesystem, a jail directory is created in `/tmp/jail-XXXXXX` (where XXXXXX are random characters). This directory is mounted as a `tmpfs` filesystem. Thus, all files created in the jail are backed by a controllable amount of memory. Memory r/w is also very fast. The size of the tmpfs is limited to `256KiB` by default. This is to prevent the jailed process from consuming all of the host's memory. A `pivot_root` syscall is performed to make the jail directory the new root. All references to `/` will now actually refer to `/tmp/jail-XXXXXX`.

Now the jail still needs necessary system files to do anything besides exist (like run our challenges). To provide these, `"/bin", "/lib", "/lib64", "/usr", "/etc", "/var", "/sbin"` are bind-mounted **from the host** into the jail as **read-only**. This is done to prevent the jailed process from modifying these files and potentially breaking the host system. It's worth noting that these are the actual directories from the host, so if you have any sensitive information in these directories, it will be readable from inside the jail.

### **Including `/etc/shadow`!**

This is why you should use this in combination with **Docker**, a chrooted busybox, a VM, or something similar.

After mounting the basic system files, the challenge directory (`dirname_in_challenges`) associated with the key is either bind-mounted or copied into the jail. If the copy option is used, the files will take from the tmpfs limit (unlike any bind-mounted directories). The optional suid bit is applied to the `file_in_dir_to_exec`. A fresh home directory (`/home/ctf`), which the ctf user has read and write access to, is created. The special files at `/dev/null`, `/dev/zero`, `/dev/(u)random`, a `/root` and `/tmp` directory are also created.

The current working directory is set to the `challenge_dir_path_in_jail`. We have now entered the jail. The challenge binary is spawned as the new `init` process while the parent (which resides in the old pid namespace) will later clean up the jail. The init process is unkillable in the new pid namespace, even by root. A fresh proc mount is created in the new pid namespace. Running `ps` now only shows the init process (bash for instance) and ps.

Root privileges are dropped and heavily restricted using linux capabilities. The `file_in_dir_to_exec` was executed as the ctf user. Once the challenge binary exits or the user closes the network connection or the time is up, the jail and connection are cleaned up.

If logging is enabled, all user input will be logged to a log file along with IP address and timestamp before even making it to the challenge.

## Building

### Clone the repo

```bash
git clone https://github.com/Nuspli/ansj.git
cd ansj
```

## Docker setup (recommended)

Use the provided [Dockerfile](Dockerfile) to run the server. The challenges will be hosted on port 31337.

```bash
sudo docker build -t ansj .
sudo docker run --privileged --cgroupns=host -d -p 31337:31337 --rm -it ansj
```

connect:

```bash
nc localhost 31337
```

## Manual setup

### Requirements

`libcap`:

```bash
sudo apt install libcap-dev
```

### Compile the binary

If any of the capability functions or the cgroups setup fails, make sure to check that your kernel supports them.

When compiling, link against `libcap` with `-lcap`.

```bash
gcc nsj.c -o nsj -lcap
```

If you want to build in debug mode (lots of additional output), define `DEBUG`:

```bash
gcc -DDEBUG nsj.c -o nsj -lcap
```

### Run

```bash
sudo ./nsj [options]
```
