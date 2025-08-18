#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <dirent.h>
#include <grp.h>
#include <pwd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <pthread.h>
#include <sys/sysmacros.h>
#include <poll.h>

// part of libcap!, link with -lcap
#include <sys/capability.h>

#ifdef DEBUG
    #define debug(code) code
#else
    #define debug(code)
#endif
#define errExit(msg) do {perror(msg); exit(EXIT_FAILURE);} while (0)
#define printfExit(fmt, ...) do {printf(fmt, ##__VA_ARGS__); exit(EXIT_FAILURE);} while (0)
#define nitems(arr) (sizeof(arr) / sizeof(arr[0]))

struct linux_dirent64 {
    unsigned long long d_ino;
    unsigned long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

struct config {
    int family;
    union {
        struct in6_addr ipv6;
        struct in_addr ipv4;
    } addr;
    in_port_t port;
    bool nin, nout, nerr, single, no_time;
    struct {
        bool set;
        rlim_t lim;
    } cpu, mem, proc;
    int conn;
    size_t fss;

    struct {
        char *dirname_in_challenges;
        char *file_in_dir_to_exec;
        char *timeout;
        char *challenge_dir_path_in_jail;
        bool display_keys;
        bool suid;
        bool copy;
    } cfg_file;
};

#define MAX_IPS 512 // todo: make this an option.
#define NOSPACE 1
#define EXCEEDED 2

struct ip_entry {
    char ip[INET6_ADDRSTRLEN];
    int connection_count;
};

struct ip_table {
    struct ip_entry entries[MAX_IPS];
    pthread_mutex_t lock;
};

struct ip_table *ip_map;
char glob_ip[INET6_ADDRSTRLEN];

int CTFUID;
char *cwd = NULL;
char *log_path = NULL;
int MAXTIME = 0;

void close_open_fds() {

    int dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    if (dir == -1) errExit("open");

    char buf[0x1000];

    while (1) {
        int nread = syscall(SYS_getdents64, dir, buf, sizeof(buf));
        if (nread == -1) errExit("getdents64");
        if (nread == 0) break; // end of directory

        for (int bpos = 0; bpos < nread;) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + bpos);
            bpos += d->d_reclen;

            int fd = atoi(d->d_name);
            if (fd == dir || fd <= 2) continue; // skip self (dir) and standard IO (0, 1, 2)
            if (close(fd) == -1) errExit("close");
        }
    }
    if (close(dir) == -1) errExit("close");
}

void delete_directory(const char *path) {

    struct dirent *entry;

    DIR *dir = opendir(path);
    if (dir == NULL) errExit("opendir");

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(full_path, &st) == -1) errExit("lstat");

        // unmount any mounted directories. it's fine if this fails.
        if (umount2(full_path, MNT_DETACH) == 0) debug(fprintf(stderr, "... unmounted: %s\n", full_path));

        if (S_ISDIR(st.st_mode)) {
            // recursively delete subdirectory
            delete_directory(full_path);
            debug(fprintf(stderr, "... removing directory %s.\n", full_path));
            if (rmdir(full_path) == -1) errExit("rmdir");

        } else {
            // delete file or symlink
            debug(fprintf(stderr, "... removing file %s.\n", full_path));
            if (unlink(full_path) == -1) errExit("unlink");
        }
    }
    if (closedir(dir) == -1) errExit("closedir");
}

void copy_directory(const char *src, const char *dst) {

    struct dirent *entry;
    DIR *dir = opendir(src);
    if (dir == NULL) errExit("opendir");

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        char full_src_path[PATH_MAX];
        char full_dst_path[PATH_MAX];
        snprintf(full_src_path, sizeof(full_src_path), "%s/%s", src, entry->d_name);
        snprintf(full_dst_path, sizeof(full_dst_path), "%s/%s", dst, entry->d_name);

        struct stat st;
        if (lstat(full_src_path, &st) == -1) errExit("lstat");

        if (S_ISDIR(st.st_mode)) {
            // recursively copy subdirectory
            if (mkdir(full_dst_path, 0755) == -1) errExit("mkdir");
            copy_directory(full_src_path, full_dst_path);

        } else {
            // copy file or symlink
            int src_fd = open(full_src_path, O_RDONLY);
            if (src_fd == -1) errExit("open");

            if (fstat(src_fd, &st) == -1) errExit("fstat");

            int dst_fd = open(full_dst_path, O_WRONLY | O_CREAT, st.st_mode);
            if (dst_fd == -1) errExit("open");

            debug(fprintf(stderr, "... copying %s to %s.\n", full_src_path, full_dst_path));
            if (sendfile(dst_fd, src_fd, NULL, st.st_size) == -1) errExit("sendfile");

            if (close(src_fd) == -1) errExit("close");
            if (close(dst_fd) == -1) errExit("close");
        }
    }
    if (closedir(dir) == -1) errExit("closedir");
}

void make_directory(const char *path) {
    char temp[PATH_MAX];
    char *p = NULL;

    snprintf(temp, sizeof(temp), "%s", path);

    for (p = temp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(temp, 0755) && errno != EEXIST) errExit("mkdir");
            *p = '/';
        }
    }

    if (mkdir(temp, 0755) && errno != EEXIST) errExit("mkdir");
}

int get_ctf_uid() {
    struct passwd *pw = getpwnam("ctf");
    if (pw == NULL) {
        debug(fprintf(stderr, "ctf user not found. creating ...\n"));
        if (system("useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf; echo \"ctf:ctf\" | chpasswd") == -1) errExit("system");
        pw = getpwnam("ctf");
        if (pw == NULL) errExit("getpwnam");
    }
    return pw->pw_uid;
}

// link with -lcap
void drop_capabilities() {

    cap_value_t cap_list[] = {
        CAP_AUDIT_CONTROL,
        CAP_AUDIT_READ,
        CAP_AUDIT_WRITE,
        CAP_BLOCK_SUSPEND,
        CAP_BPF,
        CAP_CHECKPOINT_RESTORE,
//        CAP_CHOWN, // allow chown
//        CAP_DAC_OVERRIDE, // allow bypassing file permission checks
//        CAP_DAC_READ_SEARCH,
        CAP_FOWNER,
        CAP_FSETID,
        CAP_IPC_LOCK, // mlock bad? drop
        CAP_IPC_OWNER,
        CAP_KILL,
        CAP_LEASE,
        CAP_LINUX_IMMUTABLE,
        CAP_MAC_ADMIN,
        CAP_MAC_OVERRIDE,
        CAP_MKNOD,
        CAP_NET_ADMIN,
        CAP_NET_BIND_SERVICE,
        CAP_NET_BROADCAST,
        CAP_NET_RAW,
        CAP_PERFMON,
//        CAP_SETGID, // allow setgid and setgroups
        CAP_SETFCAP,
        CAP_SETPCAP,
//        CAP_SETUID, // allow setuid
        CAP_SYS_ADMIN, // this absolutely needs to be dropped!
        CAP_SYS_BOOT,
        CAP_SYS_CHROOT,
        CAP_SYS_MODULE,
        CAP_SYS_NICE,
        CAP_SYS_PACCT,
        CAP_SYS_PTRACE,
        CAP_SYS_RAWIO,
        CAP_SYS_RESOURCE,
        CAP_SYS_TIME,
        CAP_SYS_TTY_CONFIG,
        CAP_SYSLOG,
        CAP_WAKE_ALARM
    };

    debug(fprintf(stderr, "... ... removing most capabilities from bounding set.\n"));
    for (int i = 0; i < nitems(cap_list); i++) {
        if (cap_drop_bound(cap_list[i]) == -1) errExit("cap_drop_bound");
    }
}

void timeout_handler(int sig) {
    puts("timeout!");
    exit(0);
}

void parse_config_file(struct config *cfg) {

    char key[0x100] = {0};

    if (!cfg->single) {
        printf("enter the challenge key: ");

        signal(SIGALRM, timeout_handler);
        alarm(5);
        if (fscanf(stdin, "%255s", key) != 1) exit(0);
        alarm(0);
    } debug(else fprintf(stderr, "using single challenge only.\n"));

    FILE *config_fd = fopen("./config", "r");
    if (config_fd == NULL) errExit("fopen");

    int read;
    size_t len = 0;
    char *line = NULL;

    bool display_keys = false;
    bool found = false;

    if (strcmp(key, "help") == 0) {
        puts("this service is probably used to host ctf challenges.");
        puts("in order to access a challenge, you need to know the key.");
        puts("if it hasn't been specified or doesn't work, contact the organizers.\n");
        puts("publicly available keys:");
        display_keys = true;
    }

    while ((read = getline(&line, &len, config_fd)) != -1) {

        char *keychall = strtok(line, ":");
        cfg->cfg_file.dirname_in_challenges = strtok(NULL, ":");
        cfg->cfg_file.file_in_dir_to_exec = strtok(NULL, ":");
        cfg->cfg_file.timeout = strtok(NULL, ":");
        cfg->cfg_file.challenge_dir_path_in_jail = strtok(NULL, ":");
        char *list = strtok(NULL, ":");
        
        if (display_keys && list != NULL && strcmp(list, "list") == 0) puts(keychall);

        if (cfg->single || keychall != NULL && strcmp(keychall, key) == 0) {

            char *suid_str = strtok(NULL, ":");
            char *copy_str = strtok(NULL, ":");

            if (cfg->cfg_file.dirname_in_challenges == NULL) printfExit("error in config: missing dirname_in_challenges.\n");
            if (cfg->cfg_file.file_in_dir_to_exec == NULL) printfExit("error in config: missing file_in_dir_to_exec.\n");
            if (cfg->cfg_file.timeout == NULL) printfExit("error in config: missing timeout.\n");
            if (cfg->cfg_file.challenge_dir_path_in_jail == NULL) printfExit("error in config: missing challenge_dir_path_in_jail.\n");
            if (list == NULL) printfExit("error in config: missing list.\n");
            if (suid_str == NULL) printfExit("error in config: missing suid.\n");
            if (copy_str == NULL) printfExit("error in config: missing copy.\n");

            if (strcmp(suid_str, "suid") == 0) cfg->cfg_file.suid = true;
            if (strcmp(copy_str, "copy") == 0) cfg->cfg_file.copy = true;
            MAXTIME = atoi(cfg->cfg_file.timeout);

            found = true;
            break;
        }
    }

    // do not free line. ptrs created by strtok still use it.

    if (fclose(config_fd) == EOF) errExit("fclose");

    if (!found) {
        if (!display_keys) puts("challenge not found. try 'help' if you don't know the key.");
        exit(0);
    }

    if (MAXTIME == 0) {
        printf("error in config: timeout cannot be %s\n", cfg->cfg_file.timeout);
        exit(EXIT_FAILURE);
    }

    char temp[PATH_MAX] = {0};
    snprintf(temp, sizeof(temp), "%s/challenges/%s", cwd, cfg->cfg_file.dirname_in_challenges);
    if (access(temp, F_OK) == -1) {
        printf("error in config: challenge directory not found: %s\n", temp);
        exit(EXIT_FAILURE);
    }

    strcat(temp, "/");
    strcat(temp, cfg->cfg_file.file_in_dir_to_exec);
    if (access(temp, F_OK) == -1) {
        printf("error in config: challenge binary not found: %s\n", temp);
        exit(EXIT_FAILURE);
    }

    if (*(cfg->cfg_file.challenge_dir_path_in_jail) != '/') {
        printf("error in config: challenge directory path in jail must be absolute: %s\n", cfg->cfg_file.challenge_dir_path_in_jail);
        exit(EXIT_FAILURE);
    }

    if (strlen(cfg->cfg_file.challenge_dir_path_in_jail) > PATH_MAX) {
        printf("error in config: challenge directory path in jail too long: %s\n", cfg->cfg_file.challenge_dir_path_in_jail);
        exit(EXIT_FAILURE);
    }

    // also cannot use /old, /home, /proc, /bin, /lib, /lib64, /usr, /etc, /var, /sbin
    // /old would be really bad, everything else will likely error and fail later.
    if (strstr(cfg->cfg_file.challenge_dir_path_in_jail, "old") != NULL) {
        printf("error in config: challenge directory path in jail cannot contain \"old\": %s\n", cfg->cfg_file.challenge_dir_path_in_jail);
        exit(EXIT_FAILURE);
    }

    if (cfg->cfg_file.suid && !cfg->cfg_file.copy)
        debug(fprintf(stderr, "warning: suid binaries should be copied into the jail.\n"));
}

pid_t jailed_init_pid = 0;
volatile sig_atomic_t timed_out = 0;

void timeout_handler2(int sig) {
    debug(fprintf(stderr, "timeout reached, killing challenge with pid %d ...\n", jailed_init_pid));
    if (kill(jailed_init_pid, SIGKILL) == -1 && errno != ESRCH) errExit("kill");
    puts("timeout!");
    timed_out = 1;
}

void enable_controller(const char *parent, const char *controller) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/cgroup.subtree_control", parent);
    int fd = open(path, O_WRONLY);
    if (fd == -1) errExit("open subtree_control");

    char buf[32];
    snprintf(buf, sizeof(buf), "+%s", controller);
    if (write(fd, buf, strlen(buf)) == -1) errExit("write subtree_control");

    if (close(fd) == -1) errExit("close subtree_control");
}

int setup_cgroups(const char *jail_name, struct config *cfg) {

    if (!(cfg->proc.set || cfg->cpu.set || cfg->mem.set)) {
        debug(fprintf(stderr, "no cgroup limits set, skipping cgroup setup.\n"));
        return -1; // no cgroup limits set, skip setup
    }

    char cgroup_path[PATH_MAX];
    snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup/nsj/%s", jail_name);

    make_directory("/sys/fs/cgroup/nsj");
    
    enable_controller("/sys/fs/cgroup/nsj", "pids");
    enable_controller("/sys/fs/cgroup/nsj", "cpu");
    enable_controller("/sys/fs/cgroup/nsj", "memory");

    make_directory(cgroup_path);

    // set the cgroup limits
    if (cfg->proc.set) {
        char pids_max_path[PATH_MAX];
        snprintf(pids_max_path, sizeof(pids_max_path), "%s/pids.max", cgroup_path);
        int pids_max_fd = open(pids_max_path, O_WRONLY);
        if (pids_max_fd == -1) errExit("open pids_max");
        debug(fprintf(stderr, "... setting process limit to %lu\n", cfg->proc.lim));
        dprintf(pids_max_fd, "%d", cfg->proc.lim); // should be at least 1.
        if (close(pids_max_fd) == -1) errExit("close");   
    }

    if (cfg->cpu.set) {
        char cpu_max_path[PATH_MAX];
        snprintf(cpu_max_path, sizeof(cpu_max_path), "%s/cpu.max", cgroup_path);
        int cpu_max_fd = open(cpu_max_path, O_WRONLY);
        if (cpu_max_fd == -1) errExit("open cpu_max");
        debug(fprintf(stderr, "... setting CPU limit to %d%%\n", cfg->cpu.lim));
        dprintf(cpu_max_fd, "%d %d", cfg->cpu.lim * 1000, 100000); // format: "max_period max_quota"
        if (close(cpu_max_fd) == -1) errExit("close");
    }

    if (cfg->mem.set) {
        char mem_max_path[PATH_MAX];
        snprintf(mem_max_path, sizeof(mem_max_path), "%s/memory.max", cgroup_path);
        int mem_max_fd = open(mem_max_path, O_WRONLY);
        if (mem_max_fd == -1) errExit("open mem_max");
        debug(fprintf(stderr, "... setting memory limit to %zu bytes\n", cfg->mem.lim));
        dprintf(mem_max_fd, "%zu", cfg->mem.lim); // format: "max_bytes"
        if (close(mem_max_fd) == -1) errExit("close");
    }

    char cgroup_proc_path[PATH_MAX];
    snprintf(cgroup_proc_path, sizeof(cgroup_proc_path), "%s/cgroup.procs", cgroup_path);
    int cgroup_proc_fd = open(cgroup_proc_path, O_WRONLY);
    if (cgroup_proc_fd == -1) errExit("open cgroup_proc");
    return cgroup_proc_fd;
}

void enter_jail(struct config *cfg) {

    char new_root[] = "/tmp/jail-XXXXXX";
    char *jail_name = new_root + 5; // skip "/tmp/"
    char old_root[PATH_MAX];

    debug(fprintf(stderr, "obtaining a file descriptor for the old root directory ...\n"));
    int cleanup_dirfd = open("/", O_PATH | O_DIRECTORY);
    if (cleanup_dirfd == -1) errExit("open old root");
    debug(fprintf(stderr, "... obtained file descriptor %d for the old root directory.\n", cleanup_dirfd));
    
    debug(fprintf(stderr, "creating jail root ...\n"));
    if (mkdtemp(new_root) == NULL) errExit("mkdtemp jail root");
    debug(fprintf(stderr, "... created jail root at \"%s\".\n", new_root));

    debug(fprintf(stderr, "setting up cgroup for the jail ...\n"));
    int cgroup_proc_fd = setup_cgroups(jail_name, cfg);

    char old_challenge_dir_path[PATH_MAX-2] = {0};
    snprintf(old_challenge_dir_path, sizeof(old_challenge_dir_path), "/old%s/challenges/%s", cwd, cfg->cfg_file.dirname_in_challenges);
    // example: /old/cwd/challenges/default

    char old_file_to_exec[PATH_MAX] = {0};
    snprintf(old_file_to_exec, sizeof(old_file_to_exec), "%s/%s", old_challenge_dir_path, cfg->cfg_file.file_in_dir_to_exec);
    // example: /old/cwd/challenges/default/init

    char new_file_to_exec[PATH_MAX] = {0};
    snprintf(new_file_to_exec, sizeof(new_file_to_exec), "%s/%s", cfg->cfg_file.challenge_dir_path_in_jail, cfg->cfg_file.file_in_dir_to_exec);
    // example: /challenge/init

    debug(fprintf(stderr, "splitting off into different namespace(s) ...\n"));
    if (unshare(CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWUTS|CLONE_NEWIPC) == -1) errExit("unshare");

    debug(fprintf(stderr, "... changing the old / to a private mount so that pivot_root succeeds later.\n"));
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) errExit("mount private");

    char size_option[32];
    snprintf(size_option, sizeof(size_option), "size=%zu", cfg->fss);

    debug(fprintf(stderr, "... bind-mounting the new root over itself as a tmpfs. this will also make it a 'mount point' for pivot_root() later.\n"));
    if (mount(new_root, new_root, "tmpfs", 0, size_option) == -1) errExit("mount tmpfs");

    debug(fprintf(stderr, "... creating a directory in which pivot_root will put the old root filesystem.\n"));
    snprintf(old_root, sizeof(old_root), "%s/old", new_root);
    if (mkdir(old_root, 0777) == -1) errExit("mkdir /old");

    // after this, / will refer to /tmp/jail-XXXXXX, and /old will refer to the old root filesystem
    debug(fprintf(stderr, "... pivoting the root filesystem!\n"));
    if (syscall(SYS_pivot_root, new_root, old_root) == -1) {
        // if pivot root fails here, things are really bad. the jail would have to be cleaned up manually. (unmount /tmp/jail-XXXXXX/old and rm -rf /tmp/jail-XXXXXX)
        errExit("CRITICAL ERROR: pivot_root");
    }

    debug(fprintf(stderr, "creating jail structure ...\n"));

    // mount some important directories into the jail. you can remove or add directories here.
    // a home directory, some special files under /dev, /proc and /tmp are created later.

    char *dirs[] = {"/bin", "/lib", "/lib64", "/usr", "/etc", "/var", "/sbin", NULL};
    for (char **dir = dirs; *dir; dir++) {
        char *path = *dir;
        char old_path[PATH_MAX];
        snprintf(old_path, sizeof(old_path), "/old%s", path);

        debug(fprintf(stderr, "... bind-mounting (read-only) %s into %s in the jail.\n", old_path, path));
        make_directory(path);
        if (mount(old_path, path, NULL, MS_BIND|MS_RDONLY, NULL) == -1) errExit("mount bind");
        if (mount(NULL, path, NULL, MS_REMOUNT|MS_BIND|MS_RDONLY, NULL) == -1) errExit("mount remount");
    }

    if (mkdir("/tmp", 01777) == -1) errExit("mkdir /tmp");
    if (mkdir("/dev", 0755) == -1) errExit("mkdir /dev");
    if (mknod("/dev/null", S_IFCHR|0666, makedev(1, 3)) == -1) errExit("mknod /dev/null");
    if (mknod("/dev/zero", S_IFCHR|0666, makedev(1, 5)) == -1) errExit("mknod /dev/zero");
    if (mknod("/dev/random", S_IFCHR|0666, makedev(1, 8)) == -1) errExit("mknod /dev/random");
    if (mknod("/dev/urandom", S_IFCHR|0666, makedev(1, 9)) == -1) errExit("mknod /dev/urandom");

    if (mkdir("/root", 0700) == -1) errExit("mkdir /root");

    debug(fprintf(stderr, "... creating home directory for ctf user.\n"));
    if (mkdir("/home", 0755) == -1) errExit("mkdir /home");
    if (mkdir("/home/ctf", 0750) == -1) errExit("mkdir /home/ctf");
    if (chown("/home/ctf", CTFUID, CTFUID) == -1) errExit("chown /home/ctf");

    // mount the challenge files into the new challenge directory
    // optionally make file to exec suid root to allow further setup,
    //     NOTE: THIS IS DANGEROUS AS IT CREATES AN SUID BINARY OUTSIDE OF THE JAIL. ONLY USE THIS IN COMBINATION WITH 'copy' IN THE CONFIG, UNLESS YOU KNOW WHAT YOU ARE DOING.
    // optionally copy the challenge files into the jail instead of bind-mounting them (slower). THIS IS TO DEAL WITH SUID BINARIES LIKE MENTIONED ABOVE.

    debug(fprintf(stderr, "... creating challenge directory in the jail.\n"));
    make_directory(cfg->cfg_file.challenge_dir_path_in_jail);

    char *exec_path_to_chmod;
    if (cfg->cfg_file.copy) {
        debug(fprintf(stderr, "... copying challenge files into the jail.\n"));
        copy_directory(old_challenge_dir_path, cfg->cfg_file.challenge_dir_path_in_jail);
        exec_path_to_chmod = new_file_to_exec;
    } else {
        debug(fprintf(stderr, "... bind-mounting (read-only) %s into %s in the jail.\n", old_challenge_dir_path, cfg->cfg_file.challenge_dir_path_in_jail));
        if (mount(old_challenge_dir_path, cfg->cfg_file.challenge_dir_path_in_jail, NULL, MS_BIND|MS_RDONLY, NULL) == -1) errExit("mount challenge_dir");
        if (mount(NULL, cfg->cfg_file.challenge_dir_path_in_jail, NULL, MS_REMOUNT|MS_BIND|MS_RDONLY, NULL) == -1) errExit("mount challenge_dir");
        exec_path_to_chmod = old_file_to_exec;
    }

    debug(fprintf(stderr, "... changing ownership and permissions of %s ...\n", exec_path_to_chmod));
    debug(fprintf(stderr, "... ... suid: %s.\n", cfg->cfg_file.suid ? "true" : "false"));
    
    int uid = cfg->cfg_file.suid ? 0 : CTFUID;
    int perms = cfg->cfg_file.suid ? 04755 : 0755;

    if (chown(exec_path_to_chmod, uid, uid) == -1) errExit("chown challenge");
    if (chmod(exec_path_to_chmod, perms) == -1) errExit("chmod challenge");

    debug(fprintf(stderr, "... unmounting old root directory.\n"));
    if (umount2("/old", MNT_DETACH) == -1) errExit("umount2 old"); // cleaning up jail root is not safe until real root is unmounted!
    if (rmdir("/old") == -1) errExit("rmdir old");

    debug(fprintf(stderr, "moving the current working directory into the jail.\n"));
    if (chdir(cfg->cfg_file.challenge_dir_path_in_jail) != 0) errExit("chdir challenge_dir");

    debug(fprintf(stderr, "starting new init process ...\n"));
    pid_t pid = fork();
    debug(fprintf(stderr, "... forked with pid %d.\n", pid));

    if (pid == -1) errExit("fork jail");
    if (pid == 0) {
        // continue as init (pid 1) from here on

        signal(SIGALRM, SIG_IGN);

        debug(fprintf(stderr, "bind-mounting fresh /proc into jail.\n"));
        if (mkdir("/proc", 0755) == -1) errExit("mkdir proc");
        if (mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, "hidepid=2") != 0) errExit("mount proc");
        if (mount(NULL, "/proc", NULL, MS_REMOUNT|MS_BIND|MS_RDONLY, NULL) != 0) errExit("mount proc");
        
        if (close(cleanup_dirfd) == -1) errExit("close");
        if (cgroup_proc_fd != -1 && close(cgroup_proc_fd) == -1) errExit("close cgroup_proc_fd");
        close_open_fds(); // just to be safe.

        debug(fprintf(stderr, "... dropping privileges ...\n"));

        drop_capabilities();

        debug(fprintf(stderr, "... ... setgroups(0, NULL); setgid(%d); setuid(%d);\n", CTFUID, CTFUID));
        if (setgroups(0, NULL) == -1) errExit("setgroups");
        if (setgid(CTFUID) == -1) errExit("setgid");
        if (setuid(CTFUID) == -1) errExit("setuid");

        debug(fprintf(stderr, "... launching challenge ...\n\n"));
        char *const args[] = {new_file_to_exec, NULL};

        if (!cfg->no_time) printf("your instance will die in %d seconds.\n", MAXTIME);

        if (execve(args[0], args, NULL) == -1) errExit("execve challenge");        
    }

    jailed_init_pid = pid;

    if (cgroup_proc_fd != -1) {
        debug(fprintf(stderr, "adding pid %d to jail cgroup %s.\n", pid, jail_name));
        if (dprintf(cgroup_proc_fd, "%d", pid) < 0) errExit("dprintf cgroup_proc_fd");
        if (close(cgroup_proc_fd) == -1) errExit("close cgroup_proc_fd");
    }
    
    struct sigaction sa = {0};
    sa.sa_handler = timeout_handler2;
    sigaction(SIGALRM, &sa, NULL); // do not set SA_RESTART to avoid blocking on recv after timeout.

    alarm(MAXTIME);
    
    int status;
    while ((waitpid(pid, &status, WNOHANG) == 0) && !timed_out) {

        if (log_path != NULL) {
            // stdin is pipe, check for early broken pipe.
            struct pollfd pfd = {.fd = 0, .events = POLLIN | POLLHUP | POLLERR};
            int ret = poll(&pfd, 1, 10); // 10ms timeout.

            if (ret > 0) {
                if (pfd.revents & (POLLHUP | POLLERR)) {
                    debug(fprintf(stderr, "client closed the connection. killing jail.\n"));
                    if (kill(jailed_init_pid, SIGKILL) == -1 && errno != ESRCH) errExit("kill");
                    timed_out = 1;
                }
            } else if (ret < 0 && errno != EINTR) {
                errExit("poll");
            }

        } else {
            // stdin is socket, check for early client disconnects.
            char buf;
            ssize_t r = recv(0, &buf, 1, MSG_PEEK|MSG_DONTWAIT);
            if (r == 0) {
                debug(fprintf(stderr, "client closed the connection. killing jail.\n"));
                if (kill(jailed_init_pid, SIGKILL) == -1 && errno != ESRCH) errExit("kill");
                timed_out = 1;
            } else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOTSOCK && errno != EINTR) {
                errExit("recv MSG_PEEK");
            }
        }
            
        usleep(10000); // do nothing.
    }

    alarm(0);
    signal(SIGALRM, SIG_DFL);

    // if a client closes the connection early, writes to the socket will result in SIGPIPE.
    // this could interfere with debug output, so we ignore it.
    // (note: you should always use '-se n' for debug output)
    signal(SIGPIPE, SIG_IGN);
    
    debug(fprintf(stderr, "challenge exited with status %d\n", WEXITSTATUS(status)));
    debug(fprintf(stderr, "cleaning up the jail directory ...\n"));
    debug(fprintf(stderr, "... removing files:\n"));

    chdir("/");
    delete_directory("."); // this is /tmp/jail-XXXXXX, not the real root.

    char *rel_pathname = (char *)new_root + 1;
    debug(fprintf(stderr, "... removing jail directory at %s relative to dirfd %d.\n", rel_pathname, cleanup_dirfd));
    if (unlinkat(cleanup_dirfd, rel_pathname, AT_REMOVEDIR) == -1) errExit("unlinkat jail");
    
    if (cgroup_proc_fd != -1) {
        char rel_cgroup_path[PATH_MAX];
        snprintf(rel_cgroup_path, sizeof(rel_cgroup_path), "sys/fs/cgroup/nsj/%s", jail_name);
        debug(fprintf(stderr, "... removing cgroup directory %s relative to dirfd %d.\n", rel_cgroup_path, cleanup_dirfd));
        if (unlinkat(cleanup_dirfd, rel_cgroup_path, AT_REMOVEDIR) == -1) errExit("unlinkat cgroup");
    }
    
    if (close(cleanup_dirfd) == -1) errExit("close cleanup_dirfd");
    debug(fprintf(stderr, "exiting ...\n"));
    return;
}

// PART OF THE FOLLOWING IS TAKEN FROM ynetd: https://yx7.cc/code

void help(int st, char **argv) {

    puts("Usage:");
    printf("  %s [options]\n\n", basename(argv[0]));

    puts(
        "About:\n"
        "  Lightweight(?) network service jailer.\n"
        "  Intended for hosting MULTIPLE pwn ctf challenges on a single port.\n"
        "\n"
        "Options:\n"
        "  -h,  --help                      This help text\n"
        "  -a,  --addr <addr>               IP address to bind to (default :: and 0.0.0.0).\n"
        "  -p,  --port <port>               TCP port to bind to (default 1024).\n"
        "  -s,  --single                    Serve a single challenge only. the first line of the config file is used without prompting for the key.\n"
        "  -l,  --log <path>                Log all user input and append it to a file named <path>. if <path> is '-' stdout is used.\n"
        "  -nt, --no-time                   Don't tell the user how much time their instance has.\n"
        "  -ni, --no-stdin                  Don't use the socket as stdin.\n"
        "  -no, --no-stdout                 Don't use the socket as stdout.\n"
        "  -ne, --no-stderr                 Don't use the socket as stderr. useful for debugging.\n"
        "  -lu, --limit-cpu-usage <lim>     Maximum cpu usage per connection in percent (default unchanged).\n"
        "  -lm, --limit-memory <lim>        Limit the amount of memory in bytes (default unchanged).\n"
        "  -lp, --limit-processes <lim>     Limit the number of processes (default unchanged).\n"
        "  -lc, --limit-connections <lim>   Limit the number of concurrent connections per ip (default 1).\n"
        "  -lf, --limit-tmpfs <lim>         Limit the size of tmpfs in bytes (default 262144 aka 256KiB).\n"
        "\n"
        "Config:\n"
        "  The config file is located at ./config and each line must be formatted as follows:\n"
        "\n"
        "    :key:dirname_in_challenges:file_in_dir_to_exec:timeout_in_seconds:challenge_dir_path_in_jail:list/nolist:suid/nosuid:copy/nocopy:\n"
        "\n"
        "  key:                             The unique key associated with the challenge. CANNOT BE 'help' OR CONTAIN ':' OR ' '.\n"
        "  dirname_in_challenges:           The name of the directory in ./challenges that contains the challenge files.\n"
        "  file_in_dir_to_exec:             The name of the file in dirname_in_challenges that will be executed in the jail.\n"
        "  timeout_in_seconds:              The time in seconds after which the jail will be destroyed.\n"
        "  challenge_dir_path_in_jail:      The path to the directory in the jail where the challenge files will be accessible. Must be absolute. Cannot use /old, /home, /proc, /bin, /lib, /lib64, /usr, /etc, /var, /dev, /sbin.\n"
        "  list/nolist:                     If this value is 'list', the key will be listed when the user types 'help'.\n"
        "  suid/nosuid:                     If this value is 'suid', the file_in_dir_to_exec will be made suid root. If copy is not set, this will make the file suid root outside of the jail too. YOU PROBABLY DON'T WANT THIS. USE copy FOR SUID CHALLENGES.\n"
        "  copy/nocopy:                     If this value is 'copy', the challenge directory will be copied into the jail instead of bind-mounted. This may be slower for challenges with many files.\n"
        "\n"
        "  DO NOT LEAVE ANY VALUES EMPTY. TO OPT OUT OF list OR suid OR copy, USE 'nolist' OR 'nosuid' OR 'nocopy' OR LITERALLY ANY OTHER STRING. DO NOT DO THIS:\n"
        "    :key:dirname_in_challenges:file_in_dir_to_exec::challenge_dir_path_in_jail::::\n"
    );
    exit(st);
}

void parse_args(size_t argc, char **argv, struct config *cfg) {

#define ARG_OPT(S, L, V) \
    else if (!strcmp(argv[i], (S)) || !strcmp(argv[i], (L))) { \
        (V) = true; \
        i++; \
    }

#define ARG_NUM(S, L, V, P) \
    else if (!strcmp(argv[i], (S)) || !strcmp(argv[i], (L))) { \
        if (++i >= argc) \
            help(1, argv); \
        (V) = strtol(argv[i++], NULL, 10); \
        if (P) \
            *(bool *)(P) = true; \
    }

    for (size_t i = 1; i < argc; ) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) help(0, argv);
        ARG_OPT("-ni", "--no-stdin", cfg->nin)
        ARG_OPT("-no", "--no-stdout", cfg->nout)
        ARG_OPT("-ne", "--no-stderr", cfg->nerr)
        ARG_OPT("-nt", "--no-time", cfg->no_time)
        ARG_OPT("-s", "--single", cfg->single)
        ARG_NUM("-p", "--port", cfg->port, NULL)
        ARG_NUM("-lu", "--limit-cpu-usage", cfg->cpu.lim, &cfg->cpu.set)
        ARG_NUM("-lm", "--limit-memory", cfg->mem.lim, &cfg->mem.set)
        ARG_NUM("-lp", "--limit-processes", cfg->proc.lim, &cfg->proc.set)
        ARG_NUM("-lc", "--limit-connections", cfg->conn, NULL)
        ARG_NUM("-lf", "--limit-tmpfs", cfg->fss, NULL)
        else if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--addr")) {
            if (++i >= argc)
                help(1, argv);
            if (1 == inet_pton(AF_INET6, argv[i], &cfg->addr.ipv6))
                cfg->family = AF_INET6;
            else if (1 == inet_pton(AF_INET, argv[i], &cfg->addr.ipv4))
                cfg->family = AF_INET;
            else
                errExit("inet_pton");
            ++i;
        }
        else if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--log")) {
            if (++i >= argc) help(1, argv);
            log_path = argv[i++];
        }
        else help(1, argv);
    }

#undef ARG_OPT
#undef ARG_NUM
}

void init_ip_table() {
    // MAP_ANONYMOUS will zero the memory
    ip_map = mmap(NULL, sizeof(struct ip_table), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    pthread_mutex_init(&ip_map->lock, NULL);
}

int increment_connection(const char *ip, struct config *cfg) {
    int r = NOSPACE;
    pthread_mutex_lock(&ip_map->lock);
    for (int i = 0; i < MAX_IPS; i++) {
        if (ip_map->entries[i].ip[0] == '\0') {
            strcpy(ip_map->entries[i].ip, ip);
            ip_map->entries[i].connection_count = 1;
            r = 0;
            break;
        }
        if (strcmp(ip_map->entries[i].ip, ip) == 0) {
            if (ip_map->entries[i].connection_count >= cfg->conn) {
                r = EXCEEDED;
                break;
            }
            ip_map->entries[i].connection_count++;
            r = 0;
            break;
        }
    }
    pthread_mutex_unlock(&ip_map->lock);
    return r;
}

void decrement_connection(const char *ip) {
    pthread_mutex_lock(&ip_map->lock);
    for (int i = 0; i < MAX_IPS; i++) {
        if (strcmp(ip_map->entries[i].ip, ip) == 0) {
            ip_map->entries[i].connection_count--;
            if (ip_map->entries[i].connection_count == 0)
                ip_map->entries[i].ip[0] = '\0';
            break;
        }
    }
    pthread_mutex_unlock(&ip_map->lock);
}

int bind_listen(struct config const cfg) {
    int const one = 1;
    int lsock;
    union {
       struct sockaddr_in6 ipv6;
       struct sockaddr_in ipv4;
    } addr = {0};
    socklen_t addr_len;

    if (0 > (lsock = socket(cfg.family, SOCK_STREAM, 0))) errExit("socket");

    if (setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) errExit("setsockopt");

    switch (cfg.family) {
    case AF_INET6:
        addr.ipv6.sin6_family = cfg.family;
        addr.ipv6.sin6_addr = cfg.addr.ipv6;
        addr.ipv6.sin6_port = htons(cfg.port);
        addr_len = sizeof(addr.ipv6);
        break;
    case AF_INET:
        addr.ipv4.sin_family = cfg.family;
        addr.ipv4.sin_addr = cfg.addr.ipv4;
        addr.ipv4.sin_port = htons(cfg.port);
        addr_len = sizeof(addr.ipv4);
        break;
    default:
        puts("bad address family?!\n");
        exit(1);
    }

    if (bind(lsock, (struct sockaddr *) &addr, addr_len)) errExit("bind");

    if (listen(lsock, 16)) errExit("listen");

    return lsock;
}

int infds[2];

void handler(int sig) {
    debug(fprintf(stderr, "received SIGUSR2, exiting log process ...\n"));
    exit(0);
}

pid_t log_pid;

void stdin_log(int lfd) {
    
    log_pid = getpid();
    pipe(infds); // 1===>0

    int pid = fork();
    if (pid == -1) errExit("fork log process");
    if (pid) {

        struct sigaction sa = {0};
        sa.sa_handler = handler;
        sigaction(SIGUSR2, &sa, NULL); // do not set SA_RESTART

        close(infds[0]);
        char buf[0x1000];
        while (1) {
            int r = read(0, buf, 0x1000); // read from socket
            if (r <= 0) break;
            if (waitpid(pid, NULL, WNOHANG) != 0) break;
            dprintf(lfd, "[%s-%ld]:", glob_ip, time(NULL));
            write(lfd, buf, r);
            if (write(infds[1], buf, r) == -1) break; // write to pipe (challenge process' stdin)
        }
        close(lfd);
        close(infds[1]); // this should cause a broken pipe in the child process.
        debug(fprintf(stderr, "stdin_log: exiting ...\n"));
        exit(0);
    } else {
        dup2(infds[0], 0);
        close(infds[0]);
        close(infds[1]);
    }
}

pid_t server_pid;
int logfd = -1;

void cleanup(int st, void *arg) {
    debug(fprintf(stderr, "cleaning up connection ...\n"));
    decrement_connection(glob_ip);

    if (log_path != NULL) {
        debug(fprintf(stderr, "killing log process with pid %d ...\n", log_pid));
        if (kill(log_pid, SIGUSR2) == -1 && errno != ESRCH) errExit("kill log process");
    }

    close(0);
    close(1);
    close(2);

    if (st != 0) {
        printf("jail exited with non-zero status: %d\nstopping server ...\n", st);
        kill(server_pid, SIGUSR1);
    }
}

void handle_connection(struct config cfg, int sock) {

    if (log_path != NULL) {
        if (strcmp(log_path, "-") != 0) {
            logfd = open(log_path, O_CREAT|O_RDWR|O_APPEND, 0644);
            if (logfd == -1) errExit("open log file");
        } else  {
            logfd = dup(1);
            if (logfd == -1) errExit("dup 1");
        }
    }

    // duplicate socket to stdio
    if (!cfg.nin && 0 != dup2(sock, 0)) errExit("dup2 0");
    if (!cfg.nout && 1 != dup2(sock, 1)) errExit("dup2 1");
    if (!cfg.nerr && 2 != dup2(sock, 2)) errExit("dup2 2");
    if (close(sock)) errExit("close sock");

    if (log_path != NULL) stdin_log(logfd);

    debug(fprintf(stderr, "installing exit handler ...\n"));
    if (on_exit(cleanup, NULL)) errExit("on_exit cleanup");

    parse_config_file(&cfg);
    enter_jail(&cfg);
    exit(0); // jail exits normally
}

void stop_server(int sig) {
    debug(fprintf(stderr, "stopping server ...\n"));
    pause();
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv, char **envp) {

    signal(SIGUSR1, stop_server);

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    umask(0);

    pid_t pid;
    struct sigaction sigact;
    int lsock, sock;

    struct config cfg = {
        .family = AF_INET6,
        .addr = {.ipv6 = in6addr_any},
        .port = 1024,
        .nin = false, .nout = false, .nerr = false, .single=false, .no_time=false,
        .cpu = {.set = false}, .mem = {.set = false}, .proc = {.set = false},
        .conn = 1,
        .fss = 262144
    };

    parse_args(argc, argv, &cfg);

    debug(fprintf(stderr, "checking that this is running as root ...\n"));
    if (geteuid() != 0) {puts("you must run this as root. if you are looking for the options, try '--help'."); exit(1);}

    CTFUID = get_ctf_uid();
    cwd = get_current_dir_name();
    if (cwd == NULL) errExit("get_current_dir_name");

    // do not turn dead children into zombies
    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_flags = SA_NOCLDWAIT | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sigact, 0)) errExit("sigaction SIGCHLD");

    debug(fprintf(stderr, "listening on port %d\n", cfg.port));
    lsock = bind_listen(cfg);

    init_ip_table();
    server_pid = getpid();

    while (1) {
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);

        if (0 > (sock = accept(lsock, (struct sockaddr *)&addr, &addrlen))) continue;

        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
            if (inet_ntop(AF_INET, &(addr_in->sin_addr), glob_ip, sizeof(glob_ip)) == NULL) errExit("inet_ntop");
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr;
            if (inet_ntop(AF_INET6, &(addr_in6->sin6_addr), glob_ip, sizeof(glob_ip)) == NULL) errExit("inet_ntop");
        } else {
            continue;
        }

        debug(fprintf(stderr, "connection from %s\n", glob_ip));

        int r = increment_connection(glob_ip, &cfg);
        if (r == EXCEEDED) {
            debug(fprintf(stderr, "dropped. too many connections from this ip.\n"));
            write(sock, "too many connections from this ip.\n", 35);
            if (close(sock)) errExit("close sock");
            continue;
        }
        if (r == NOSPACE) {
            debug(fprintf(stderr, "dropped. no space in ip table.\n"));
            write(sock, "internal error. try again later.\n", 33);
            if (close(sock)) errExit("close sock");
            continue;
        }

        if ((pid = fork())) {
            if (pid == -1) decrement_connection(glob_ip);
            if (close(sock)) errExit("close sock");
            continue; // parent
        }

        // child
        if (close(lsock)) errExit("close lsock");
        if (0 > setsid()) errExit("setsid");

        signal(SIGUSR1, SIG_IGN);

        handle_connection(cfg, sock);
    }
    return 0;
}
