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
#include <sys/resource.h>
#include <sys/sysmacros.h>
#include <dirent.h>
#include <grp.h>
#include <pwd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <poll.h>
#include <linux/close_range.h>
#include <linux/sched.h>
#include <sched.h>

// part of libcap!, link with -lcap
#include <sys/capability.h>

#ifdef DEBUG
    #define debug(code) code
#else
    #define debug(code)
#endif
#define dbg_msg(fmt, ...) debug(fprintf(stderr, fmt, ##__VA_ARGS__))
#define err_exit(msg) do {perror(msg); exit(EXIT_FAILURE);} while (0)
#define printf_exit(fmt, ...) do {printf(fmt, ##__VA_ARGS__); exit(EXIT_FAILURE);} while (0)
#define nitems(arr) (sizeof(arr) / sizeof(arr[0]))

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
        char *list;
        bool suid;
        bool copy;
        char *argv_1_to_pass;
    } cfg_file;
};

#define NOSPACE 1
#define EXCEEDED 2

struct ip_entry {
    char ip[INET6_ADDRSTRLEN];
    int connection_count;
};

struct ip_table {
    struct ip_entry *entries;
    int entries_size;
    pthread_mutex_t lock;
};

struct ip_table *ip_map;
char glob_ip[INET6_ADDRSTRLEN];

int ctf_uid;
char *cwd = NULL;
char *log_path = NULL;
int max_time = 0;

void delete_directory(const char *path) {

    struct dirent *entry;

    DIR *dir = opendir(path);
    if (dir == NULL) err_exit("opendir");

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(full_path, &st) == -1) err_exit("lstat");

        // unmount any mounted directories. it's fine if this fails.
        if (umount2(full_path, MNT_DETACH) == 0) {
            dbg_msg("... unmounted: %s\n", full_path);
        }

        if (S_ISDIR(st.st_mode)) {
            // recursively delete subdirectory
            delete_directory(full_path);
            dbg_msg("... removing directory %s.\n", full_path);
            if (rmdir(full_path) == -1) err_exit("rmdir");

        } else {
            // delete file or symlink
            dbg_msg("... removing file %s.\n", full_path);
            if (unlink(full_path) == -1) err_exit("unlink");
        }
    }
    if (closedir(dir) == -1) err_exit("closedir");
}

void copy_directory(const char *src, const char *dst) {

    struct dirent *entry;
    DIR *dir = opendir(src);
    if (dir == NULL) err_exit("opendir");

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        char full_src_path[PATH_MAX];
        char full_dst_path[PATH_MAX];
        snprintf(full_src_path, sizeof(full_src_path), "%s/%s", src, entry->d_name);
        snprintf(full_dst_path, sizeof(full_dst_path), "%s/%s", dst, entry->d_name);

        struct stat st;
        if (lstat(full_src_path, &st) == -1) err_exit("lstat");

        if (S_ISDIR(st.st_mode)) {
            // recursively copy subdirectory
            if (mkdir(full_dst_path, 0755) == -1) err_exit("mkdir");
            copy_directory(full_src_path, full_dst_path);

        } else {
            // copy file or symlink
            int src_fd = open(full_src_path, O_RDONLY);
            if (src_fd == -1) err_exit("open");

            if (fstat(src_fd, &st) == -1) err_exit("fstat");

            int dst_fd = open(full_dst_path, O_WRONLY | O_CREAT, st.st_mode);
            if (dst_fd == -1) err_exit("open");

            dbg_msg("... copying %s to %s.\n", full_src_path, full_dst_path);
            if (sendfile(dst_fd, src_fd, NULL, st.st_size) == -1) err_exit("sendfile");

            if (close(src_fd) == -1) err_exit("close");
            if (close(dst_fd) == -1) err_exit("close");
        }
    }
    if (closedir(dir) == -1) err_exit("closedir");
}

void make_directory(const char *path) {
    char temp[PATH_MAX];
    char *p = NULL;

    snprintf(temp, sizeof(temp), "%s", path);

    for (p = temp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(temp, 0755) && errno != EEXIST) err_exit("mkdir");
            *p = '/';
        }
    }

    if (mkdir(temp, 0755) && errno != EEXIST) err_exit("mkdir");
}

int get_ctf_uid() {
    struct passwd *pw = getpwnam("ctf");
    if (pw == NULL) {
        dbg_msg("ctf user not found. creating ...\n");
        if (system("useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf; echo \"ctf:ctf\" | chpasswd") == -1) err_exit("system");
        pw = getpwnam("ctf");
        if (pw == NULL) err_exit("getpwnam");
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
//        CAP_CHOWN, allow chown
//        CAP_DAC_OVERRIDE, allow bypassing file permission checks
//        CAP_DAC_READ_SEARCH, allow bypassing file permission checks
        CAP_FOWNER,
        CAP_FSETID,
        CAP_IPC_LOCK,
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
//        CAP_SETGID, allow setgid and setgroups
        CAP_SETFCAP,
        CAP_SETPCAP,
//        CAP_SETUID, allow setuid
        CAP_SYS_ADMIN, // this absolutely needs to be dropped!!!
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

    dbg_msg("... ... removing most capabilities from bounding set.\n");
    for (int i = 0; i < nitems(cap_list); i++) {
        if (cap_drop_bound(cap_list[i]) == -1) err_exit("cap_drop_bound");
    }
}

void key_timeout_handler(int sig) {
    puts("timeout!");
    exit(0);
}

void parse_config_file(struct config *cfg) {

    char key[0x100] = {0};

    if (!cfg->single) {
        printf("enter the challenge key: ");

        signal(SIGALRM, key_timeout_handler);
        alarm(5);
        if (fscanf(stdin, "%255s", key) != 1) exit(0);
        alarm(0);
    } debug(else fprintf(stderr, "using single challenge only.\n"));

    FILE *config_fd = fopen("./config", "r");
    if (config_fd == NULL) err_exit("fopen");

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
        cfg->cfg_file.list = strtok(NULL, ":");
        
        if (display_keys && cfg->cfg_file.list != NULL && strcmp(cfg->cfg_file.list, "list") == 0) puts(keychall);

        if (cfg->single || keychall != NULL && strcmp(keychall, key) == 0) {

            char *suid_str = strtok(NULL, ":");
            char *copy_str = strtok(NULL, ":");
            cfg->cfg_file.argv_1_to_pass = strtok(NULL, ":");
            if (cfg->cfg_file.argv_1_to_pass[0] == '\n') cfg->cfg_file.argv_1_to_pass = NULL;

            if (cfg->cfg_file.dirname_in_challenges == NULL) printf_exit("error in config: missing dirname_in_challenges.\n");
            if (cfg->cfg_file.file_in_dir_to_exec == NULL) printf_exit("error in config: missing file_in_dir_to_exec.\n");
            if (cfg->cfg_file.timeout == NULL) printf_exit("error in config: missing timeout.\n");
            if (cfg->cfg_file.challenge_dir_path_in_jail == NULL) printf_exit("error in config: missing challenge_dir_path_in_jail.\n");
            if (cfg->cfg_file.list == NULL) printf_exit("error in config: missing list.\n");
            if (suid_str == NULL) printf_exit("error in config: missing suid.\n");
            if (copy_str == NULL) printf_exit("error in config: missing copy.\n");

            if (strcmp(suid_str, "suid") == 0) cfg->cfg_file.suid = true;
            if (strcmp(copy_str, "copy") == 0) cfg->cfg_file.copy = true;
            max_time = atoi(cfg->cfg_file.timeout);

            found = true;
            break;
        }
    }

    // do not free line. ptrs created by strtok still use it.

    if (fclose(config_fd) == EOF) err_exit("fclose");

    if (!found) {
        if (!display_keys) puts("challenge not found. try 'help' if you don't know the key.");
        exit(0);
    }

    if (max_time == 0) {
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
        dbg_msg("warning: suid binaries should be copied into the jail.\n");
}

pid_t jailed_init_pid = 0;
volatile sig_atomic_t timed_out = 0;

void challenge_timeout_handler(int sig) {
    dbg_msg("timeout reached, killing challenge with pid %d ...\n", jailed_init_pid);
    if (kill(jailed_init_pid, SIGKILL) == -1 && errno != ESRCH) err_exit("kill");
    puts("timeout!");
    timed_out = 1;
}

void enable_controller(const char *parent, const char *controller) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/cgroup.subtree_control", parent);
    int fd = open(path, O_WRONLY);
    if (fd == -1) err_exit("open subtree_control");

    char buf[32];
    snprintf(buf, sizeof(buf), "+%s", controller);
    if (write(fd, buf, strlen(buf)) == -1) err_exit("write subtree_control");

    if (close(fd) == -1) err_exit("close subtree_control");
}

void setup_nsj_cgroup(struct config *cfg) {
    if (!(cfg->proc.set || cfg->cpu.set || cfg->mem.set)) {
        dbg_msg("no cgroup limits set, skipping nsj cgroup setup.\n");
        return; // no cgroup limits set, skip setup
    }
    make_directory("/sys/fs/cgroup/nsj");
    enable_controller("/sys/fs/cgroup/nsj", "pids");
    enable_controller("/sys/fs/cgroup/nsj", "cpu");
    enable_controller("/sys/fs/cgroup/nsj", "memory");
}

int setup_cgroups(const char *jail_name, struct config *cfg) {

    if (!(cfg->proc.set || cfg->cpu.set || cfg->mem.set)) {
        dbg_msg("no cgroup limits set, skipping per jail cgroup setup.\n");
        return -1;
    }
    
    char cgroup_path[PATH_MAX];
    snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup/nsj/%s", jail_name);

    make_directory(cgroup_path);
    int cgroup_jail_dir_fd = open(cgroup_path, O_PATH);

    // set the cgroup limits
    if (cfg->proc.set) {
        char pids_max_path[PATH_MAX];
        snprintf(pids_max_path, sizeof(pids_max_path), "%s/pids.max", cgroup_path);
        int pids_max_fd = open(pids_max_path, O_WRONLY);
        if (pids_max_fd == -1) err_exit("open pids_max");
        dbg_msg("... setting process limit to %lu\n", cfg->proc.lim);
        dprintf(pids_max_fd, "%ld", cfg->proc.lim); // should be at least 1.
        if (close(pids_max_fd) == -1) err_exit("close");   
    }

    if (cfg->cpu.set) {
        char cpu_max_path[PATH_MAX];
        snprintf(cpu_max_path, sizeof(cpu_max_path), "%s/cpu.max", cgroup_path);
        int cpu_max_fd = open(cpu_max_path, O_WRONLY);
        if (cpu_max_fd == -1) err_exit("open cpu_max");
        dbg_msg("... setting CPU limit to %ld%%\n", cfg->cpu.lim);
        dprintf(cpu_max_fd, "%ld %d", cfg->cpu.lim * 1000, 100000); // format: "max_period max_quota"
        if (close(cpu_max_fd) == -1) err_exit("close");
    }

    if (cfg->mem.set) {
        char mem_max_path[PATH_MAX];
        snprintf(mem_max_path, sizeof(mem_max_path), "%s/memory.max", cgroup_path);
        int mem_max_fd = open(mem_max_path, O_WRONLY);
        if (mem_max_fd == -1) err_exit("open mem_max");
        dbg_msg("... setting memory limit to %zu bytes\n", cfg->mem.lim);
        dprintf(mem_max_fd, "%zu", cfg->mem.lim); // format: "max_bytes"
        if (close(mem_max_fd) == -1) err_exit("close");
    }

    return cgroup_jail_dir_fd;
}

void enter_jail(struct config *cfg) {

    char new_root[] = "/tmp/jail-XXXXXX";
    char *jail_name = new_root + 5; // skip "/tmp/"
    char old_root[PATH_MAX];

    dbg_msg("obtaining a file descriptor for the old root directory ...\n");
    int cleanup_dirfd = open("/", O_PATH | O_DIRECTORY);
    if (cleanup_dirfd == -1) err_exit("open old root");
    dbg_msg("... obtained file descriptor %d for the old root directory.\n", cleanup_dirfd);
    
    dbg_msg("creating jail root ...\n");
    if (mkdtemp(new_root) == NULL) err_exit("mkdtemp jail root");
    dbg_msg("... created jail root at \"%s\".\n", new_root);

    dbg_msg("setting up cgroups for the jail ...\n");
    int cgroup_jail_dir_fd = setup_cgroups(jail_name, cfg);

    char old_challenge_dir_path[PATH_MAX-2] = {0};
    snprintf(old_challenge_dir_path, sizeof(old_challenge_dir_path), "/old%s/challenges/%s", cwd, cfg->cfg_file.dirname_in_challenges);
    // example: /old/cwd/challenges/default

    char old_file_to_exec[PATH_MAX] = {0};
    snprintf(old_file_to_exec, sizeof(old_file_to_exec), "%s/%s", old_challenge_dir_path, cfg->cfg_file.file_in_dir_to_exec);
    // example: /old/cwd/challenges/default/init

    char new_file_to_exec[PATH_MAX] = {0};
    snprintf(new_file_to_exec, sizeof(new_file_to_exec), "%s/%s", cfg->cfg_file.challenge_dir_path_in_jail, cfg->cfg_file.file_in_dir_to_exec);
    // example: /challenge/init

    dbg_msg("splitting off into different namespace(s) ...\n");
    if (unshare(CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWUTS|CLONE_NEWIPC) == -1) err_exit("unshare");

    dbg_msg("... changing the old / to a private mount so that pivot_root succeeds later.\n");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) err_exit("mount private");

    char size_option[32];
    snprintf(size_option, sizeof(size_option), "size=%zu", cfg->fss);

    dbg_msg("... bind-mounting the new root over itself as a tmpfs. this will also make it a 'mount point' for pivot_root() later.\n");
    if (mount(new_root, new_root, "tmpfs", 0, size_option) == -1) err_exit("mount tmpfs");

    dbg_msg("... creating a directory in which pivot_root will put the old root filesystem.\n");
    snprintf(old_root, sizeof(old_root), "%s/old", new_root);
    if (mkdir(old_root, 0777) == -1) err_exit("mkdir /old");

    // after this, / will refer to /tmp/jail-XXXXXX, and /old will refer to the old root filesystem
    dbg_msg("... pivoting the root filesystem!\n");
    if (syscall(SYS_pivot_root, new_root, old_root) == -1) {
        // if pivot root fails here, things are really bad. the jail would have to be cleaned up manually. (unmount /tmp/jail-XXXXXX/old and rm -rf /tmp/jail-XXXXXX)
        err_exit("CRITICAL ERROR: pivot_root");
    }

    dbg_msg("creating jail structure ...\n");

    // mount some important directories into the jail. you can remove or add directories here.
    // a home directory, some special files under /dev, /proc and /tmp are also created.

    char *dirs[] = {"/bin", "/lib", "/lib64", "/usr", "/etc", "/var", "/sbin", NULL};
    for (char **dir = dirs; *dir; dir++) {
        char *path = *dir;
        char old_path[PATH_MAX];
        snprintf(old_path, sizeof(old_path), "/old%s", path);

        dbg_msg("... bind-mounting (read-only) %s into %s in the jail.\n", old_path, path);
        make_directory(path);
        if (mount(old_path, path, NULL, MS_BIND|MS_RDONLY, NULL) == -1) err_exit("mount bind");
        if (mount(NULL, path, NULL, MS_REMOUNT|MS_BIND|MS_RDONLY, NULL) == -1) err_exit("mount remount");
    }

    if (mkdir("/tmp", 01777) == -1) err_exit("mkdir /tmp");
    if (mkdir("/dev", 0755) == -1) err_exit("mkdir /dev");
    if (mknod("/dev/null", S_IFCHR|0666, makedev(1, 3)) == -1) err_exit("mknod /dev/null");
    if (mknod("/dev/zero", S_IFCHR|0666, makedev(1, 5)) == -1) err_exit("mknod /dev/zero");
    if (mknod("/dev/random", S_IFCHR|0666, makedev(1, 8)) == -1) err_exit("mknod /dev/random");
    if (mknod("/dev/urandom", S_IFCHR|0666, makedev(1, 9)) == -1) err_exit("mknod /dev/urandom");

    if (mkdir("/root", 0700) == -1) err_exit("mkdir /root");

    dbg_msg("... creating home directory for ctf user.\n");
    if (mkdir("/home", 0755) == -1) err_exit("mkdir /home");
    if (mkdir("/home/ctf", 0750) == -1) err_exit("mkdir /home/ctf");
    if (chown("/home/ctf", ctf_uid, ctf_uid) == -1) err_exit("chown /home/ctf");

    // mount the challenge files into the new challenge directory
    // optionally make file to exec suid root to allow further setup,
    //     NOTE: THIS IS DANGEROUS AS IT CREATES AN SUID BINARY OUTSIDE OF THE JAIL. ONLY USE THIS IN COMBINATION WITH 'copy' IN THE CONFIG, UNLESS YOU KNOW WHAT YOU ARE DOING.
    // optionally copy the challenge files into the jail instead of bind-mounting them (slower). THIS IS TO DEAL WITH SUID BINARIES LIKE MENTIONED ABOVE.

    dbg_msg("... creating challenge directory in the jail.\n");
    make_directory(cfg->cfg_file.challenge_dir_path_in_jail);

    char *exec_path_to_chmod;
    if (cfg->cfg_file.copy) {
        dbg_msg("... copying challenge files into the jail.\n");
        copy_directory(old_challenge_dir_path, cfg->cfg_file.challenge_dir_path_in_jail);
        exec_path_to_chmod = new_file_to_exec;
    } else {
        dbg_msg("... bind-mounting (read-only) %s into %s in the jail.\n", old_challenge_dir_path, cfg->cfg_file.challenge_dir_path_in_jail);
        if (mount(old_challenge_dir_path, cfg->cfg_file.challenge_dir_path_in_jail, NULL, MS_BIND|MS_RDONLY, NULL) == -1) err_exit("mount challenge_dir");
        if (mount(NULL, cfg->cfg_file.challenge_dir_path_in_jail, NULL, MS_REMOUNT|MS_BIND|MS_RDONLY, NULL) == -1) err_exit("mount challenge_dir");
        exec_path_to_chmod = old_file_to_exec;
    }

    dbg_msg("... changing ownership and permissions of %s ...\n", exec_path_to_chmod);
    dbg_msg("... ... suid: %s.\n", cfg->cfg_file.suid ? "true" : "false");
    
    int uid = cfg->cfg_file.suid ? 0 : ctf_uid;
    int perms = cfg->cfg_file.suid ? 04755 : 0755;

    if (chown(exec_path_to_chmod, uid, uid) == -1) err_exit("chown challenge");
    if (chmod(exec_path_to_chmod, perms) == -1) err_exit("chmod challenge");

    dbg_msg("... unmounting old root directory.\n");
    if (umount2("/old", MNT_DETACH) == -1) err_exit("umount2 old");
    // cleaning up jail root is not safe until real root is unmounted!
    // if you have to manually clean up a jail, MAKE SURE /old is not mounted anymore.
    if (rmdir("/old") == -1) err_exit("rmdir old");

    dbg_msg("moving the current working directory into the jail.\n");
    if (chdir(cfg->cfg_file.challenge_dir_path_in_jail) != 0) err_exit("chdir challenge_dir");

    dbg_msg("starting new init process ...\n");
    pid_t pid;
    
    if (cgroup_jail_dir_fd != -1) {

        // use CLONE_INTO_CGROUP instead of forking and then adding the jailed process to the jail cgroup
        // because doing it like that would be racy.

        struct clone_args cl_args = {0};

        cl_args.flags = CLONE_INTO_CGROUP;
        cl_args.exit_signal = SIGCHLD;
        cl_args.cgroup = cgroup_jail_dir_fd;

        pid = syscall(SYS_clone3, &cl_args, sizeof(struct clone_args));
        dbg_msg("... cloned with pid %d.\n", pid);
        if (pid == -1) err_exit("clone jail");
    } else {
        pid = fork();
        dbg_msg("... forked with pid %d.\n", pid);
        if (pid == -1) err_exit("fork jail");
    }

    if (pid == 0) {
        // continue as init (pid 1) in the new pid namespace from here on

        signal(SIGALRM, SIG_IGN);

        dbg_msg("bind-mounting fresh /proc into jail.\n");
        if (mkdir("/proc", 0755) == -1) err_exit("mkdir proc");
        if (mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, "hidepid=2") != 0) err_exit("mount proc");
        if (mount(NULL, "/proc", NULL, MS_REMOUNT|MS_BIND|MS_RDONLY, NULL) != 0) err_exit("mount proc");
        
        if (close(cleanup_dirfd) == -1) err_exit("close");
        if (cgroup_jail_dir_fd != -1 && close(cgroup_jail_dir_fd) == -1) err_exit("close cgroup_jail_dir_fd");

        // close open fds except stin/out/err just to be safe
        if (close_range(3, ~0U, CLOSE_RANGE_UNSHARE) == -1) err_exit("close_range");

        dbg_msg("... dropping privileges ...\n");

        drop_capabilities();

        dbg_msg("... ... setgroups(0, NULL); setgid(%d); setuid(%d);\n", ctf_uid, ctf_uid);
        if (setgroups(0, NULL) == -1) err_exit("setgroups");
        if (setgid(ctf_uid) == -1) err_exit("setgid");
        if (setuid(ctf_uid) == -1) err_exit("setuid");

        dbg_msg("... launching challenge %s %s ...\n\n", new_file_to_exec, cfg->cfg_file.argv_1_to_pass);
        char *const args[] = {new_file_to_exec, cfg->cfg_file.argv_1_to_pass, NULL};

        if (!cfg->no_time) printf("your instance will die in %d seconds.\n", max_time);

        if (execve(args[0], args, NULL) == -1) err_exit("execve challenge");        
    }

    jailed_init_pid = pid;

    struct sigaction sa = {0};
    sa.sa_handler = challenge_timeout_handler;
    sigaction(SIGALRM, &sa, NULL); // do not set SA_RESTART to avoid blocking on recv after timeout.

    alarm(max_time);
    
    int status;
    while ((waitpid(pid, &status, WNOHANG) == 0) && !timed_out) {

        if (log_path != NULL) {
            // stdin is pipe, check for early broken pipe.
            struct pollfd pfd = {.fd = 0, .events = POLLIN | POLLHUP | POLLERR};
            int ret = poll(&pfd, 1, 10); // 10ms timeout.

            if (ret > 0) {
                if (pfd.revents & (POLLHUP | POLLERR)) {
                    dbg_msg("client closed the connection. killing jail.\n");
                    if (kill(jailed_init_pid, SIGKILL) == -1 && errno != ESRCH) err_exit("kill");
                    timed_out = 1;
                }
            } else if (ret < 0 && errno != EINTR) {
                err_exit("poll");
            }

        } else {
            // stdin is socket, check for early client disconnects.
            char buf;
            ssize_t r = recv(0, &buf, 1, MSG_PEEK|MSG_DONTWAIT);
            if (r == 0) {
                dbg_msg("client closed the connection. killing jail.\n");
                if (kill(jailed_init_pid, SIGKILL) == -1 && errno != ESRCH) err_exit("kill");
                timed_out = 1;
            } else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOTSOCK && errno != EINTR) {
                err_exit("recv MSG_PEEK");
            }
        }
            
        usleep(10000); // do nothing for 0.01s.
    }

    alarm(0);
    signal(SIGALRM, SIG_DFL);

    // if a client closes the connection early, writes to the socket will result in SIGPIPE.
    // this could interfere with debug output, so we ignore it.
    // (note: you should always use '-ne' for debug output)
    signal(SIGPIPE, SIG_IGN);
    
    dbg_msg("challenge exited with status %d\n", WEXITSTATUS(status));
    dbg_msg("cleaning up the jail directory ...\n");
    dbg_msg("... removing files:\n");

    chdir("/");
    delete_directory("."); // this is /tmp/jail-XXXXXX, not the real root.

    char *rel_pathname = (char *)new_root + 1;
    dbg_msg("... removing jail directory at %s relative to dirfd %d.\n", rel_pathname, cleanup_dirfd);
    if (unlinkat(cleanup_dirfd, rel_pathname, AT_REMOVEDIR) == -1) err_exit("unlinkat jail");
    
    if (cgroup_jail_dir_fd != -1) {

        char rel_cgroup_path[PATH_MAX];
        char killpath[PATH_MAX];
        snprintf(rel_cgroup_path, sizeof(rel_cgroup_path), "sys/fs/cgroup/nsj/%s", jail_name);
        snprintf(killpath, sizeof(killpath), "sys/fs/cgroup/nsj/%s/cgroup.kill", jail_name);

        dbg_msg("... killing cgroup %s by writing to %s relative to dirfd %d.\n", rel_cgroup_path, killpath, cleanup_dirfd);
        int fd = openat(cleanup_dirfd, killpath, O_WRONLY);
        if (fd != -1) {
            write(fd, "1", 1);
            close(fd);
        }

        dbg_msg("... removing cgroup directory %s relative to dirfd %d.\n", rel_cgroup_path, cleanup_dirfd);
        while (1) {
            int r = unlinkat(cleanup_dirfd, rel_cgroup_path, AT_REMOVEDIR);
            if ((r == 0) || (r == -1 && errno == ENOENT)) break;
            usleep(1000); // (wait 0.001s) for cgroup to be removed.
        }
    }
    
    if (close(cleanup_dirfd) == -1) err_exit("close cleanup_dirfd");
    dbg_msg("exiting ...\n");
    return;
}

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
        "  -s,  --single                    Serve a single challenge only. The first line of the config file is used without prompting for the key.\n"
        "  -l,  --log <path>                Log all user input and append it to a file named <path>. If <path> is '-', stdout is used.\n"
        "  -nt, --no-time                   Don't tell the user how much time their instance has.\n"
        "  -ni, --no-stdin                  Don't use the socket as stdin.\n"
        "  -no, --no-stdout                 Don't use the socket as stdout.\n"
        "  -ne, --no-stderr                 Don't use the socket as stderr. Useful for debugging.\n"
        "  -lu, --limit-cpu-usage <lim>     Maximum cpu usage per connection in percent (default unchanged).\n"
        "  -lm, --limit-memory <lim>        Limit the amount of memory per connection in bytes (default unchanged).\n"
        "  -lp, --limit-processes <lim>     Limit the number of processes per connection (default unchanged).\n"
        "  -lc, --limit-connections <lim>   Limit the number of concurrent connections per ip (default 1).\n"
        "  -lf, --limit-tmpfs <lim>         Limit the size of tmpfs in bytes for each connection (default 262144 aka 256KiB).\n"
        "  -li, --limit-ip-entries <lim>    Limit the number of unique IPs that can have a connection at the same time (default 512).\n"
        "\n"
        "Config:\n"
        "  The config file is located at ./config and each line must be formatted as follows:\n"
        "\n"
        "    :key:dirname_in_challenges:file_in_dir_to_exec:timeout_in_seconds:challenge_dir_path_in_jail:list/nolist:suid/nosuid:copy/nocopy:secret:\n"
        "\n"
        "  key:                             The unique key associated with the challenge. CANNOT BE 'help' OR CONTAIN ':' OR ' '.\n"
        "  dirname_in_challenges:           The name of the directory in ./challenges that contains the challenge files.\n"
        "  file_in_dir_to_exec:             The name of the file in dirname_in_challenges that will be executed in the jail.\n"
        "  timeout_in_seconds:              The time in seconds after which the jail will be destroyed.\n"
        "  challenge_dir_path_in_jail:      The path to the directory in the jail where the challenge files will be accessible. Must be absolute. Cannot use /old, /home, /proc, /bin, /lib, /lib64, /usr, /etc, /var, /dev, /sbin.\n"
        "  list/nolist:                     If this value is 'list', the key will be listed when the user types 'help'.\n"
        "  suid/nosuid:                     If this value is 'suid', the file_in_dir_to_exec will be made suid root. If copy is not set, this will make the file suid root outside of the jail too. YOU PROBABLY DON'T WANT THIS. USE copy FOR SUID CHALLENGES.\n"
        "  copy/nocopy:                     If this value is 'copy', the challenge directory will be copied into the jail instead of bind-mounted. This may be slower for challenges with many files.\n"
        "  secret:                          OPTIONAL secret value passed to the challenge executable as the first argument (argv[1]). The final ':' may be omitted if 'secret' should end in a newline.\n"
        "\n"
        "  DO NOT LEAVE ANY VALUES EXCEPT 'secret' EMPTY. TO OPT OUT OF list OR suid OR copy, USE 'nolist' OR 'nosuid' OR 'nocopy' OR LITERALLY ANY OTHER STRING. DO NOT DO THIS:\n"
        "    :key:dirname_in_challenges:file_in_dir_to_exec::challenge_dir_path_in_jail::::\n"
    );

    if (st == 1) {
        puts("\nerror: missing or invalid argument(s):");
        putchar(' ');
        for (; *argv; argv++) {
            printf(" %s", *argv);
        }
        putchar('\n');
        puts("read above for more information.");
    }

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
        if ((V) == 0) { \
            printf("error: invalid argument for %s: %s\n", argv[i-2], argv[i-1]); \
            help(1, argv); \
        } \
        if (P) *(bool *)(P) = true; \
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
        ARG_NUM("-li", "--limit-ip-entries", ip_map->entries_size, NULL)
        else if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--addr")) {
            if (++i >= argc)
                help(1, argv);
            if (1 == inet_pton(AF_INET6, argv[i], &cfg->addr.ipv6))
                cfg->family = AF_INET6;
            else if (1 == inet_pton(AF_INET, argv[i], &cfg->addr.ipv4))
                cfg->family = AF_INET;
            else
                err_exit("inet_pton");
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
    
    ip_map->entries = mmap(NULL, ip_map->entries_size * sizeof(struct ip_entry), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ip_map->entries == MAP_FAILED) err_exit("mmap ip_map->entries");
    pthread_mutexattr_t mattr;
    if (pthread_mutexattr_init(&mattr) != 0) err_exit("pthread_mutexattr_init");
    if (pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED) != 0) err_exit("pthread_mutexattr_setpshared");
    if (pthread_mutex_init(&ip_map->lock, &mattr) != 0) err_exit("pthread_mutex_init");
    pthread_mutexattr_destroy(&mattr);
}

int increment_connection(const char *ip, struct config *cfg) {
    int r = NOSPACE;
    pthread_mutex_lock(&ip_map->lock);
    for (int i = 0; i < ip_map->entries_size; i++) {
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
    for (int i = 0; i < ip_map->entries_size; i++) {
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

    if (0 > (lsock = socket(cfg.family, SOCK_STREAM, 0))) err_exit("socket");

    if (setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) err_exit("setsockopt");

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

    if (bind(lsock, (struct sockaddr *) &addr, addr_len)) err_exit("bind");

    if (listen(lsock, 16)) err_exit("listen");

    return lsock;
}

void log_exit_signal_handler(int sig) {
    dbg_msg("received signal: %d, exiting log process ...\n", sig);
    exit(0);
}

pid_t log_pid;

void stdin_log(int lfd) {
    
    log_pid = getpid();
    
    int infds[2];
    pipe(infds); // 1===>0

    int pid = fork();
    if (pid == -1) err_exit("fork log process");
    if (pid) {

        struct sigaction sa = {0};
        sa.sa_handler = log_exit_signal_handler;
        sigaction(SIGUSR2, &sa, NULL); // do not set SA_RESTART

        close(infds[0]);
        char buf[0x1000];
        while (1) {
            int r = read(0, buf, 0x1000); // read from socket
            if (r <= 0) break;
            if (waitpid(pid, NULL, WNOHANG) != 0) break;
            dprintf(lfd, "[%s-%d-%ld]:", glob_ip, pid, time(NULL));
            write(lfd, buf, r);
            if (write(infds[1], buf, r) == -1) break; // write to pipe (challenge process' stdin)
        }
        close(lfd);
        close(infds[1]); // this should cause a broken pipe in the child process.
        dbg_msg("stdin_log: exiting ...\n");
        exit(0);
    } else {
        dup2(infds[0], 0);
        close(infds[0]);
        close(infds[1]);
    }
}

pid_t server_pid;

void cleanup(int st, void *arg) {
    dbg_msg("cleaning up connection ...\n");
    decrement_connection(glob_ip);

    if (log_path != NULL) {
        dbg_msg("killing log process with pid %d ...\n", log_pid);
        if (kill(log_pid, SIGUSR2) == -1 && errno != ESRCH) err_exit("kill log process");
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
    
    int logfd = -1;
    if (log_path != NULL) {
        if (strcmp(log_path, "-") != 0) {
            logfd = open(log_path, O_CREAT|O_RDWR|O_APPEND, 0644);
            if (logfd == -1) err_exit("open log file");
        } else  {
            logfd = dup(1);
            if (logfd == -1) err_exit("dup 1");
        }
    }

    // duplicate socket to stdio
    if (!cfg.nin && 0 != dup2(sock, 0)) err_exit("dup2 0");
    if (!cfg.nout && 1 != dup2(sock, 1)) err_exit("dup2 1");
    if (!cfg.nerr && 2 != dup2(sock, 2)) err_exit("dup2 2");
    if (close(sock)) err_exit("close sock");

    if (log_path != NULL) stdin_log(logfd);

    dbg_msg("installing exit handler ...\n");
    if (on_exit(cleanup, NULL)) err_exit("on_exit cleanup");

    parse_config_file(&cfg);
    enter_jail(&cfg);
    exit(0); // jail exits normally
}

void stop_server(int sig) {
    dbg_msg("stopping server ...\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {

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

    // MAP_ANONYMOUS will zero the memory
    ip_map = mmap(NULL, sizeof(struct ip_table), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ip_map == MAP_FAILED) err_exit("mmap ip_table");
    
    ip_map->entries_size = 512; // default, gets overwritten by parse_args if -li is used

    parse_args(argc, argv, &cfg);

    dbg_msg("checking that this is running as root ...\n");
    if (geteuid() != 0) {puts("you must run this as root. if you are looking for the options, try '--help'."); exit(1);}

    ctf_uid = get_ctf_uid();
    cwd = get_current_dir_name();
    if (cwd == NULL) err_exit("get_current_dir_name");

    // do not turn dead children into zombies
    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_flags = SA_NOCLDWAIT | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sigact, 0)) err_exit("sigaction SIGCHLD");

    dbg_msg("listening on port %d\n", cfg.port);
    lsock = bind_listen(cfg);

    init_ip_table();
    server_pid = getpid();

    setup_nsj_cgroup(&cfg);

    while (1) {
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);

        if (0 > (sock = accept(lsock, (struct sockaddr *)&addr, &addrlen))) continue;

        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
            if (inet_ntop(AF_INET, &(addr_in->sin_addr), glob_ip, sizeof(glob_ip)) == NULL) err_exit("inet_ntop");
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr;
            if (inet_ntop(AF_INET6, &(addr_in6->sin6_addr), glob_ip, sizeof(glob_ip)) == NULL) err_exit("inet_ntop");
        } else {
            continue;
        }

        dbg_msg("connection from %s\n", glob_ip);

        int r = increment_connection(glob_ip, &cfg);
        if (r == EXCEEDED) {
            dbg_msg("dropped. too many connections from this ip.\n");
            write(sock, "too many connections from this ip.\n", 35);
            if (close(sock)) err_exit("close sock");
            continue;
        }
        if (r == NOSPACE) {
            dbg_msg("dropped. no space in ip table.\n");
            write(sock, "internal error. try again later.\n", 33);
            if (close(sock)) err_exit("close sock");
            continue;
        }

        if ((pid = fork())) {
            if (pid == -1) decrement_connection(glob_ip);
            if (close(sock)) err_exit("close sock");
            continue; // parent
        }

        // child
        if (close(lsock)) err_exit("close lsock");
        if (0 > setsid()) err_exit("setsid");

        signal(SIGUSR1, SIG_IGN);

        handle_connection(cfg, sock);
    }
    return 0;
}
