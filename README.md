# ansj - a network service jailer

## WARNING!

Use with caution.
This is a personal learning project to better understand modern sandboxing techniques.
I am neither a security expert, nor an experienced C programmer.
I am not responsible for any damage caused by this project.
(In fact, while developing it, I accidentally deleted half of my file system).

## About

This is a lightweight(?) network service jailer.
It is intended for hosting **MULTIPLE** pwn ctf challenges on a **SINGLE** port. It aims to offer a securely sandboxed, fast, and customizable environment to untrusted users.
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
  -s,  --single                    Serve a single challenge only. The first line of the config file is used without prompting for the key.
  -l,  --log <path>                Log all user input and append it to a file named <path>. If <path> is '-', stdout is used.
  -nt, --no-time                   Don't tell the user how much time their instance has.
  -ni, --no-stdin                  Don't use the socket as stdin.
  -no, --no-stdout                 Don't use the socket as stdout.
  -ne, --no-stderr                 Don't use the socket as stderr. Useful for debugging.
  -lu, --limit-cpu-usage <lim>     Maximum cpu usage per connection in percent (default unchanged).
  -lm, --limit-memory <lim>        Limit the amount of memory per connection in bytes (default unchanged).
  -lp, --limit-processes <lim>     Limit the number of processes per connection (default unchanged).
  -lc, --limit-connections <lim>   Limit the number of concurrent connections per ip (default 1).
  -lf, --limit-tmpfs <lim>         Limit the size of tmpfs in bytes for each connection (default 262144 aka 256KiB).
```

## Setup

### config

The `config` file is used to set up the files inside the jail (flag, binaries) as well as the time after which the jail is destroyed. It also holds the key associated with the challenge. Users will be prompted for this key upon connecting to the server and can thus access multiple challenges on the same port.

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

This repo comes with four common use case examples.
- The [bash](/challenges/default/) challenge may be kept as a way for users to explore the file system and get a feel for the environment. It also aims to show **how to correctly use a setup/init binary** to customize the jail and create an suid setup.
- The [bof](/challenges/unpriv_bof_example/) challenge is a classic buffer overflow that never executes any code as root.
- The [python](/challenges/python_example/) challenge is to demonstrate how to get python code running, but note that there might be complications with python due to the minimal file system of the jail.
- The [rootshell](/challenges/rootshell_example/) challenge gives you a root shell inside the jail to test its limitations and security. For more information on the examples refer to the source code directly.

## Building and running

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

Make sure you have read and understood the [examples](#examples) and [how it works](#how-it-works).

### Requirements

- A regular cgroup v2 mount at `/sys/fs/cgroup`
- `libcap`:

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

## Notes and Limitations

There are several trade-offs between security and convenience that I had to consider while making this. If you care more about functionality in the jail and less about security, or the other way around, you may decide to make changes in the following aspects:

---

#### `tmpfs` filesystem

The filesystem in the jail is a `tmpfs` mount because that makes it easy to limit its size. Some system calls like `fallocate()` and other functionality may not be available on a tmpfs filesystem however, compared to an `ext4` filesystem for example.

---

#### Per IP Connection limit

When the per IP connection limit is set to 1, the server may drop a new connection even though the old one has already been closed by the client. This can happen when the new connection request arrives before the jail from the previous connection was fully cleaned up. For challenges that require brute forcing, it may be wise to set this limit > 1.

---

#### Web challenges

In theory, it should be possible to host (static) websites inside the jail, but I haven't tested this as it's not the intention. Either using the `--single` option or by using `GET` or `POST` as a key, possibly in combination with `--no-time`.

---

#### Capabilities

Some system calls will fail inside the jail by design, even as root due to missing capabilities. If you absolutely need one of these capabilities for a challenge, you can remove it from `cap_list` in `drop_capabilities()`. Be sure to know what implications those capabilities have and how they might be used to escape the jail or mess with the underlying system.

---

#### About seccomp

ansj does not use seccomp, simply because capabilities already restrict the 'dangerous' system calls. Heavy seccomp restrictions only make sense in challenge specific context and thus it is left up to the developer/deployer to use seccomp for their challenges, or not.

---

#### init.c

In order to set up the jail in a way that requires certain root priviliges, it is necessary to use an init binary and specify `suid` in the config. It's not possible to use a typical setup bash script (`setup.sh` in place of `init`) because the suid bit is ignored for script files (those using an #!interpreter). 

If you want all challenges to start as `root` instead of `ctf`, in which case executing a bash script will actually run as root, simply replace these lines in nsj.c:

```c
        if (setgroups(0, NULL) == -1) err_exit("setgroups");
        if (setgid(ctf_uid) == -1) err_exit("setgid");
        if (setuid(ctf_uid) == -1) err_exit("setuid");
```

with a call to `setuid(0)`.

If you just want to execute a setup.sh script as root instead of doing the entire setup in an init binary, you can call setuid(0) in the init binary and then execute setup.sh.

---

#### `copy` vs. `nocopy` and instance speed

Copying the challenge files into each jail on each connection takes time and also eats memory as part of the tmpfs limit. This is an issue when challenges require large files (for example a custom libc/ld) in the challenge directory.

When `nocopy` is specified, the entire challenge directory is mounted read-only, which is very fast, but prevents a setup binary from making modifications to the challenge directory (like unlinking itself or moving a flag file). For this reason, it proves to be difficult to create a fast suid setup similar to the [default](/challenges/default/) example when a custom libc is also required.

There is currently no good solution to this issue, but I may add something in the future.

Of course you can use `nocopy` and drop the user directly into the challenge instead of a shell, but then they won't be able to inspect the challenge files. A possible workaround is to make a separate entry in the config and hint towards the option to download the challenge files using a download key. You may implement such a setup like this:

init.c:
```c
// gcc -s -Wl,--build-id=none init.c -o init
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv) {

    setvbuf(stdout, NULL, _IONBF, 0);

    puts("[INFO] to keep this instance fast, you will be dropped directly into the challenge.");
    puts("[INFO] you can download the challenge files using this command:");
    puts("[INFO]   echo 'download_<challenge_key>' | nc <host> <port> | tail -n +2 > files.zip && unzip files.zip");
    // tail skips the 'your instance will die in XXX seconds.' message

    char *const args[] = {"chall", NULL};
    execve("chall", args, NULL);
}
```

download.c:
```c
// gcc -s -Wl,--build-id=none download.c -o download
#include <unistd.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>

int main() {

    int fd = open("files.zip", O_RDONLY);
    
    struct stat st;
    fstat(fd, &st);

    sendfile(1, fd, NULL, st.st_size);
    close(fd);
}
```

challenge directory
```txt
.
├── chall
├── download
├── download.c
├── files.zip
├── flag
├── init
├── init.c
├── ld-linux-x86-64.so.2
└── libc.so.6
```

config:
```txt
:chall_key:chall_dir:init:600:/challenge:nolist:nosuid:nocopy:
:download_chall_key:chall_dir:download:60:/challenge:nolist:nosuid:nocopy:
```

!!! make sure that `files.zip` does not contain the actual flag. !!!

---

## How it works

To use **namespaces**, **capabilities**, **cgroups**, etc, the program must be run as root (or rather requires certain capabilities that usually only root has). The program will also make sure that a `ctf` user exists. If it doesn't, it will be created with the password `ctf`.

The ynetd based server keeps accepting connections and limits the connections per IP. Each connection will then prompt for a key (and time out after 5 seconds if no key is entered). The config line containing the key (if it exists) will be parsed.

The jail is created in a new mount namespace that doesn't share the pid and network namespaces with the host. This means the jailed process can't access the host's network or processes. The new pid namespace along with a fresh /proc mount is important as it prohibits a sandbox escape via setns to the host's pid namespace.

To isolate the filesystem, a jail directory is created in `/tmp/jail-XXXXXX` (where XXXXXX are random characters). This directory is mounted as a `tmpfs` filesystem. Thus, all files created in the jail are backed by a controllable amount of memory. Memory r/w is also very fast. The size of the tmpfs is limited to `256KiB` by default. This is to prevent the jailed process from consuming all of the host's memory. A new cgroup with the same jail name is created if pid/cpu/mem limits are set through the options. A `pivot_root` syscall is performed to make the jail directory the new root. All references to `/` will now actually refer to `/tmp/jail-XXXXXX`.

Now the jail still needs necessary system files to do anything besides exist (like run our challenges). To provide these, `"/bin", "/lib", "/lib64", "/usr", "/etc", "/var", "/sbin"` are bind-mounted **from the host** into the jail as **read-only**. This is done to prevent the jailed process from modifying these files and potentially breaking the host system. It's worth noting that these are the actual directories from the host, so if you have any sensitive information in these directories, it will be readable from inside the jail.

!!! **Including `/etc/shadow`!** !!!

This is why you should use this in combination with **Docker**, a chrooted busybox, a VM, or something similar.

After mounting the basic system files, the challenge directory (`dirname_in_challenges`) associated with the key is either bind-mounted or copied into the jail. If the copy option is used, the files will take from the tmpfs limit (unlike any bind-mounted directories). The optional suid bit is applied to the `file_in_dir_to_exec`. A fresh home directory (`/home/ctf`), which the ctf user has read and write access to, is created. The special files at `/dev/null`, `/dev/zero`, `/dev/(u)random`, a `/root` and `/tmp` directory are also created.

The current working directory is set to the `challenge_dir_path_in_jail`. We have now entered the jail. The challenge binary is spawned as the new `init` process while the parent (which resides in the old pid namespace) will later clean up the jail. The init process is unkillable in the new pid namespace, even by root. A fresh proc mount is created in the new pid namespace. Running `ps` now only shows the init process (bash for instance) and ps.

Root privileges are dropped and heavily restricted using linux capabilities. The `file_in_dir_to_exec` is executed as the ctf user, but even if retaining uid 0 through an suid setup, the user has very limited capabilities. Once the challenge binary exits or the user closes the network connection or the time is up, the jail, cgroup and connection are cleaned up.

If logging is enabled, all user input is logged to a log file along with an IP address and timestamp before even making it to the challenge.
