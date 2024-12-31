# ansj - a network service jailer

## DISCLAIMER

Do not trust my code, it's probably not secure. Do not use this unless you've extensively reviewed the code and understand what it does. This is a personal project and I am not responsible for any damage caused by it. (In fact, while developing this, I accidentally deleted half of my file system). I am neither a security expert, nor an experienced C programmer. This is a learning project to better understand modern sandboxing techniques.

## About

Lightweight? network service jailer.
Intended for hosting MULTIPLE pwn ctf challenges on a single port.
For more information including the required setup and config format, see [setup](#setup) section.

## Usage

```txt
  nsj [options]
```

## Options

```txt
  -h        : this help text
  -a <addr> : IP address to bind to (default :: and 0.0.0.0)
  -p <port> : TCP port to bind to (default 1024)
  -si [y/n] : use socket as stdin? (default y)
  -so [y/n] : use socket as stdout? (default y)
  -se [y/n] : use socket as stderr? (default y)
  -lt <lim> : limit cpu time in seconds (default unchanged)
  -lm <lim> : limit amount of memory in bytes (default unchanged)
  -lp <lim> : limit number of processes (default unchanged)
  -lc <lim> : limit number of concurrent connections per ip (default 1)
  -lf <lim> : limit size of tmpfs in bytes (default 262144 aka 256KiB)
```

## Setup

### config

The config file is used to set up the files in the jail (flag, binaries) as well as the time after which the jail is destroyed. It also holds the key associated with the challenge. Users will be prompted for this key and can thus access multiple challenges on the same port.

Every line in the config must follow the format:

```txt
:key:dirname_in_challenges:file_in_dir_to_exec:timeout_in_seconds:challenge_dir_path_in_jail:list/nolist:suid/nosuid:copy/nocopy:
```

| Field | Description |
| --- | --- |
| **key** | the unique key associated with the challenge. CANNOT BE "help" OR CONTAIN ":", "[space]". |
| **dirname_in_challenges** | the name of the directory in ./challenges that contains the challenge files. |
| **file_in_dir_to_exec** | the name of the file in dirname_in_challenges that will be executed in the jail. |
| **timeout_in_seconds** | the time in seconds after which the jail will be destroyed. |
| **challenge_dir_path_in_jail** | the path to the directory in the jail where the challenge files will be accessible. |
| **list/nolist** | if this value is "list", the key will be listed when the user types "help". |
| **suid/nosuid** | if this value is "suid", the file_in_dir_to_exec will be made suid root. if copy is not set, this will make the file suid root outside of the jail too. YOU PROBABLY DON'T WANT THIS. USE copy FOR SUID CHALLENGES. |
| **copy/nocopy** | if this value is "copy", the challenge directory will be copied into the jail instead of bind-mounted. this may be slower for challenges with many files. |


```txt
DO NOT LEAVE ANY VALUES EMPTY. TO OPT OUT OF list OR suid OR copy, USE "nolist" OR "nosuid" OR "nocopy" OR LITERALLY ANY OTHER STRING. DO NOT DO THIS: 
:key:dirname_in_challenges:file_in_dir_to_exec::challenge_dir_path_in_jail::::
```

## Examples

This repo comes with three common use case examples. The [bash](/challenges/default/) challenge may be kept as a way for users to explore the file system and get a feel for the environment. It also aims to show how to correctly use a setup/init binary to customize the jail. The [bof](/challenges/unpriv_bof_example/) challenge is a classic buffer overflow that never executes any code as root. The [rootshell](/challenges/rootshell_example/) challenge gives you a root shell inside the jail to test it's limitations and security. Yes you heard that right. I claim that not even root can do anything meaningful in the jail. If there's something I missed, please reach out. For more information on the examples refer to the source code.

## How it works

To use **namespaces** and **capabilities**, the program must be run as root. The program will also make sure a `ctf` user exists. If it doesn't, it will be created with the password `ctf`.

The ynetd based server keeps accepting connections and applies ressource limits. Each connection will then prompt for a key and time out after 5 seconds if no key is entered. The config line containing the key (if it exists) will be parsed.

The jail is created in a new mount namespace that doesn't share the pid and network namespaces with the host. This means the jailed process can't access the host's network or processes. The new pid namespace along with a fresh /proc mount is important as it prohibits a sandbox escape via setns to the host's pid namespace.

To isolate the filesystem, a jail directory is created in `/tmp/jail-XXXXXX` (where XXXXXX are random characters). This directory is mounted as a `tmpfs` filesystem. This means that all files created in the jail are backed by a controllable amount of memory. Memory r/w is also very fast. The size of the tmpfs is limited to `256KiB` by default. This is to prevent the jailed process from consuming all of the host's memory. A `pivot_root` syscall is performed to make the jail directory the new root. All references to `/` will now actually refer to `/tmp/jail-XXXXXX`.

Now the jail still needs necessary system files to do anything besides exist (like run our challenges). To provide these, `"/bin", "/lib", "/lib64", "/usr", "/etc", "/var", "/dev", "/sbin"` are bind-mounted **from the host** into the jail as **read-only**. This is done to prevent the jailed process from modifying these files and potentially breaking the host system. It's worth noting that these are the actual directories from the host, so if you have any sensitive information in these directories, it may be readable from the jail. In that case, you should use this in combination with **Docker**, a chrooted busybox, a VM, or something similar (which is recommended anyway).

After mounting the basic system files, the challenge directory (`dirname_in_challenges`) associated with the key is either bind-mounted or copied into the jail. If the copy option is used, the files will take from the tmpfs limit (unlike any bind-mounted directories). The optional suid bit is applied to the `file_in_dir_to_exec`. A fresh home directory to which the ctf user has read and write access is created.

The current working directory is set to the `challenge_dir_path_in_jail`. We have now entered the jail. A new `init` process is spawned and will later clean up the jail. The init process is unkillable, even for root. A fresh proc mount is created in the new pid namespace. Running `ps aux` now only shows the init process (if root because the /proc mount uses hidepid=2), bash and ps.

Finally, the challenge process is spawned. Root privileges are dropped and heavily restricted using linux capabilities. The `file_in_dir_to_exec` is now executed as the ctf user. The init process will wait for the challenge process to exit or for the timeout to be reached. Then it will clean up the jail and exit itself.

## Building

`libcap` is required. For ubuntu:

```bash
sudo apt install libcap-dev
```

If any of the capability functions fail, make sure you check your kernel supports them. Link against `libcap` with `-lcap`.

```bash
gcc nsj.c -o nsj -lcap
```

If you want to build in debug mode (lots of additional output), define `DEBUG`:

```bash
gcc -DDEBUG nsj.c -o nsj -lcap
```
