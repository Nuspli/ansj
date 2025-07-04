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

// part of libcap!, link with -lcap
#include <sys/capability.h>

#ifdef DEBUG
    #define debug(code) code
#else
    #define debug(code)
#endif
#define errExit(msg) do {perror(msg); exit(EXIT_FAILURE);} while (0)
#define err_Exit(msg) do {perror(msg); _exit(EXIT_FAILURE);} while (0)
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
    bool in, out, err;
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

#define MAX_IPS 512
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
        CAP_DAC_OVERRIDE,
        CAP_DAC_READ_SEARCH,
        CAP_FOWNER,
        CAP_FSETID,
//        CAP_IPC_LOCK, // allow mmap
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

    printf("enter the challenge key: ");
    char key[0x100];

    signal(SIGALRM, timeout_handler);
    alarm(5);
    if (fscanf(stdin, "%255s", key) != 1) exit(0);
    alarm(0);
    signal(SIGALRM, SIG_IGN);

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
        puts("publically available keys:");
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

        if (keychall != NULL && strcmp(keychall, key) == 0) {

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

void enter_jail(struct config *cfg, int logfd) {

    char new_root[] = "/tmp/jail-XXXXXX";
    char old_root[PATH_MAX];

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

    debug(fprintf(stderr, "creating jail structure ...\n"));
    debug(fprintf(stderr, "... creating jail root ...\n"));
    if (mkdtemp(new_root) == NULL) errExit("mkdtemp");
    debug(fprintf(stderr, "... ... created jail root at \"%s\".\n", new_root));

    debug(fprintf(stderr, "... changing the old / to a private mount so that pivot_root succeeds later.\n"));
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) errExit("mount");

    char size_option[32];
    snprintf(size_option, sizeof(size_option), "size=%zu", cfg->fss);

    debug(fprintf(stderr, "... bind-mounting the new root over itself as a tmpfs. this will also make it a 'mount point' for pivot_root() later.\n"));
    if (mount(new_root, new_root, "tmpfs", 0, size_option) == -1) errExit("mount");

    debug(fprintf(stderr, "... creating a directory in which pivot_root will put the old root filesystem.\n"));
    snprintf(old_root, sizeof(old_root), "%s/old", new_root);
    if (mkdir(old_root, 0777) == -1) errExit("mkdir");

    debug(fprintf(stderr, "... obtaining a file descriptor for the old root directory ...\n"));
    int cleanup_dirfd = open("/", O_DIRECTORY);
    if (cleanup_dirfd == -1) errExit("open");
    debug(fprintf(stderr, "... ... obtained file descriptor %d for the old root directory.\n", cleanup_dirfd));

    // after this, / will refer to /tmp/jail-XXXXXX, and /old will refer to the old root filesystem
    debug(fprintf(stderr, "... pivoting the root filesystem!\n"));
    if (syscall(SYS_pivot_root, new_root, old_root) == -1) {
        // if pivot root fails, things are really bad. the jail would have to be cleaned up manually. (unmount /tmp/jail-XXXXXX/old and rm -rf /tmp/jail-XXXXXX)
        errExit("CRITICAL ERROR: pivot_root");
    }

    char *dirs[] = {"/bin", "/lib", "/lib64", "/usr", "/etc", "/var", "/sbin", NULL};
    for (char **dir = dirs; *dir; dir++) {
        char *path = *dir;
        char old_path[PATH_MAX];
        snprintf(old_path, sizeof(old_path), "/old%s", path);

        debug(fprintf(stderr, "... bind-mounting (read-only) %s into %s in the jail.\n", old_path, path));
        if (mkdir(path, 0755) == -1) errExit("mkdir");
        if (mount(old_path, path, NULL, MS_BIND|MS_RDONLY, NULL) == -1) errExit("mount");
        if (mount(NULL, path, NULL, MS_REMOUNT|MS_BIND|MS_RDONLY, NULL) == -1) errExit("mount");
    }

    // mount the challenge files into the new challenge directory
    // optionally make file to exec suid root to allow further setup,
    //     NOTE: THIS IS DANGEROUS AS IT CREATES AN SUID BINARY OUTSIDE OF THE JAIL. ONLY USE THIS IN COMBINATION WITH 'copy' IN THE CONFIG, UNLESS YOU KNOW WHAT YOU ARE DOING.
    // optionally copy the challenge files into the jail instead of bind-mounting them (slower). THIS IS TO DEAL WITH SUID BINARIES LIKE MENTIONED ABOVE.

    debug(fprintf(stderr, "... creating challenge directory in the jail.\n"));
    // like mkdir -p
    char temp[4096];
    char *p = NULL;

    snprintf(temp, sizeof(temp), "%s", cfg->cfg_file.challenge_dir_path_in_jail);

    for (p = temp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(temp, 0755) && errno != EEXIST) errExit("mkdir");
            *p = '/';
        }
    }

    if (mkdir(temp, 0755) && errno != EEXIST) errExit("mkdir");

    char *exec_path_to_chmod;
    if (cfg->cfg_file.copy) {
        debug(fprintf(stderr, "... copying challenge files into the jail.\n"));
        copy_directory(old_challenge_dir_path, cfg->cfg_file.challenge_dir_path_in_jail);
        exec_path_to_chmod = new_file_to_exec;
    } else {
        debug(fprintf(stderr, "... bind-mounting (read-only) %s into %s in the jail.\n", old_challenge_dir_path, cfg->cfg_file.challenge_dir_path_in_jail));
        if (mount(old_challenge_dir_path, cfg->cfg_file.challenge_dir_path_in_jail, NULL, MS_BIND|MS_RDONLY, NULL) == -1) errExit("mount");
        if (mount(NULL, cfg->cfg_file.challenge_dir_path_in_jail, NULL, MS_REMOUNT|MS_BIND|MS_RDONLY, NULL) == -1) errExit("mount");
        exec_path_to_chmod = old_file_to_exec;
    }

    debug(fprintf(stderr, "... changing ownership and permissions of %s ...\n", exec_path_to_chmod));
    debug(fprintf(stderr, "... ... suid: %s.\n", cfg->cfg_file.suid ? "true" : "false"));
    
    int uid = cfg->cfg_file.suid ? 0 : CTFUID;
    int perms = cfg->cfg_file.suid ? 04755 : 0755;

    if (chown(exec_path_to_chmod, uid, uid) == -1) errExit("chown");
    if (chmod(exec_path_to_chmod, perms) == -1) errExit("chmod");

    debug(fprintf(stderr, "... unmounting old root directory.\n"));
    if (umount2("/old", MNT_DETACH) == -1) errExit("umount2"); // cleaning up jail root is not safe until real root is unmounted!
    if (rmdir("/old") == -1) errExit("rmdir");

    debug(fprintf(stderr, "... creating home directory for ctf user.\n"));
    if (mkdir("/home", 0755) == -1) errExit("mkdir");
    if (mkdir("/home/ctf", 0750) == -1) errExit("mkdir");
    if (chown("/home/ctf", CTFUID, CTFUID) == -1) errExit("chown");

    debug(fprintf(stderr, "moving the current working directory into the jail.\n"));
    if (chdir(cfg->cfg_file.challenge_dir_path_in_jail) != 0) errExit("chdir");

    if (chmod("/", 0755) == -1) errExit("chmod"); // I forgot why I have this here, but it's probably important.

    debug(fprintf(stderr, "starting new init process ...\n"));
    pid_t init_pid = fork();
    debug(fprintf(stderr, "... forked with init_pid %d.\n", init_pid));
    if (init_pid == -1) errExit("fork");
    if (init_pid != 0) {wait(NULL); _exit(0);} // keep the (useless) parent around until the child is done. _exit to avoid atexit handler being called twice.

    // continue as init (pid 1) from here on

    debug(fprintf(stderr, "bind-mounting fresh /proc into jail.\n"));
    if (mkdir("/proc", 0755) == -1) errExit("mkdir");
    if (mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, "hidepid=2") != 0) errExit("mount");
    if (mount(NULL, "/proc", NULL, MS_REMOUNT|MS_BIND|MS_RDONLY, NULL) != 0) errExit("mount");

    printf("your instance will die in %d seconds.\n", MAXTIME);
    
    debug(fprintf(stderr, "forking off challenge process ...\n"));
    pid_t pid = fork();
    debug(fprintf(stderr, "... forked with pid %d.\n", pid));

    if (pid == -1) errExit("fork");
    if (pid == 0) {
        close_open_fds();

        debug(fprintf(stderr, "... dropping privileges ...\n"));

        drop_capabilities();

        debug(fprintf(stderr, "... ... setgroups(0, NULL); setgid(%d); setuid(%d);\n", CTFUID, CTFUID));
        if (setgroups(0, NULL) == -1) errExit("setgroups");
        if (setgid(CTFUID) == -1) errExit("setgid");
        if (setuid(CTFUID) == -1) errExit("setuid");

        debug(fprintf(stderr, "... launching challenge ...\n\n"));
        char *const args[] = {new_file_to_exec, NULL};
        if (execve(new_file_to_exec, args, NULL) == -1) errExit("execve");
        
    } else {
        // init process, cannot be killed (or otherwise messed with?)
        int status;
        int t = 0;
        while ((waitpid(pid, &status, WNOHANG) == 0) && ((logfd != -1) ? (fcntl(logfd, F_GETFL) != -1) : 1)) {
            if (t >= MAXTIME) {puts("timeout!"); break;}
            sleep(1);
            t++;
        }

        debug(fprintf(stderr, "challenge exited with status %d\n", WEXITSTATUS(status)));
        debug(fprintf(stderr, "cleaning up the jail directory ...\n"));
        debug(fprintf(stderr, "... removing files:\n"));

        if (chdir("/") == -1) errExit("chdir"); // this is /tmp/jail-XXXXXX, not the real root.
        delete_directory(".");

        char *rel_pathname = (char *)new_root + 1;
        debug(fprintf(stderr, "... removing jail directory at %s relative to dirfd %d\n", rel_pathname, cleanup_dirfd));
        if (unlinkat(cleanup_dirfd, rel_pathname, AT_REMOVEDIR) == -1) errExit("unlinkat");
    }
    if (close(cleanup_dirfd) == -1) errExit("close");
    debug(fprintf(stderr, "exiting ...\n"));
    return;
}

/*
PART OF THE FOLLOWING IS TAKEN FROM ynetd: https://yx7.cc/code
*/

void help(int st, char **argv) {

    puts("Usage:");
    printf("  %s [options]\n\n", basename(argv[0]));

    puts(
        "About:\n"
        "  Lightweight network service jailer.\n"
        "  Intended for hosting MULTIPLE pwn ctf challenges on a single port.\n"
        "  For more information including the required setup and config format, see README.md.\n\n"

        "Options:\n"
        "  -h        : this help text\n"
        "  -a <addr> : IP address to bind to (default :: and 0.0.0.0)\n"
        "  -p <port> : TCP port to bind to (default 1024)\n"
        "  -l <path> : log all user input and append it to a file named <path>. if <path> is '-' stdout is used\n"
        "  -si [y/n] : use socket as stdin? (default y)\n"
        "  -so [y/n] : use socket as stdout? (default y)\n"
        "  -se [y/n] : use socket as stderr? (default y)\n"
        "  -lt <lim> : limit cpu time in seconds (default unchanged)\n"
        "  -lm <lim> : limit amount of memory in bytes (default unchanged)\n"
        "  -lp <lim> : limit number of processes (default unchanged)\n"
        "  -lc <lim> : limit number of concurrent connections per ip (default 1)\n"
        "  -lf <lim> : limit size of tmpfs in bytes (default 262144 aka 256KiB)\n"
        );
    exit(st);
}

void parse_args(size_t argc, char **argv, struct config *cfg) {

#define ARG_YESNO(S, L, V) \
    else if (!strcmp(argv[i], (S)) || !strcmp(argv[i], (L))) { \
        if (++i >= argc) \
            help(1, argv); \
        if (argv[i][1] || (*argv[i] != 'y' && *argv[i] != 'n')) \
            help(1, argv); \
        (V) = *argv[i++] == 'y'; \
    }

#define ARG_NUM(S, L, V, P) \
    else if (!strcmp(argv[i], (S)) || !strcmp(argv[i], (L))) { \
        if (++i >= argc) \
            help(1, argv); \
        (V) = strtol(argv[i++], NULL, 10); \
        if (P) \
            * (bool *) (P) = true; \
    }

    for (size_t i = 1; i < argc; ) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) help(0, argv);
        ARG_YESNO("-si", "--stdin", cfg->in)
        ARG_YESNO("-so", "--stdout", cfg->out)
        ARG_YESNO("-se", "--stderr", cfg->err)
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
        ARG_NUM("-p", "--port", cfg->port, NULL)
        ARG_NUM("-lt", "--limit-time", cfg->cpu.lim, &cfg->cpu.set)
        ARG_NUM("-lm", "--limit-memory", cfg->mem.lim, &cfg->mem.set)
        ARG_NUM("-lp", "--limit-processes", cfg->proc.lim, &cfg->proc.set)
        ARG_NUM("-lc", "--limit-connections", cfg->conn, NULL)
        ARG_NUM("-lf", "--limit-tmpfs", cfg->fss, NULL)
        else if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--log")) {
            if (++i >= argc) help(1, argv);
            log_path = argv[i++];
        }
        else help(1, argv);
    }

#undef ARG_YESNO
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

void stdin_log(int logfd) {
    pipe(infds); // 1===>0

    int pid = fork();
    if (pid) {
        close(infds[0]);
        char buf[0x1000];
        while (1) {
            int r = read(0, buf, 0x1000);
            if (r <= 0) break;
            if (waitpid(pid, NULL, WNOHANG) != 0) break; // todo
            if (write(infds[1], buf, r) == -1) break; // todo: find better solution. this is a race condition
            dprintf(logfd, "[%s-%ld]:", glob_ip, time(NULL));
            write(logfd, buf, r);
        }
        close(infds[1]);
        close(logfd); // this should trigger cleanup of jail
        exit(0);
    } else {
        dup2(infds[0], 0);
        close(infds[1]);
    }
}

pid_t server_pid;

void cleanup(int st, void *arg) {
    debug(fprintf(stderr, "cleaning up connection ...\n"));
    decrement_connection(glob_ip);
    close(infds[0]);
    if (st != 0) {
        printf("jail exited with non-zero status: %d\nstopping server ...\n", st);
        kill(server_pid, SIGUSR1);
    }
}

void handle_connection(struct config cfg, int sock) {

    struct rlimit rlim;

    // set resource limits
    if (cfg.cpu.set) {
        rlim.rlim_cur = rlim.rlim_max = cfg.cpu.lim;
        if (0 > setrlimit(RLIMIT_CPU, &rlim))
            errExit("setrlimit");
    }
    if (cfg.mem.set) {
        rlim.rlim_cur = rlim.rlim_max = cfg.mem.lim;
        debug(fprintf(stderr, "setting memory limit to %lu\n", cfg.mem.lim));
#ifndef RLIMIT_AS
        if (0 > setrlimit(RLIMIT_DATA, &rlim))
#else
        if (0 > setrlimit(RLIMIT_AS, &rlim))
#endif
            errExit("setrlimit");
    }
    if (cfg.proc.set) {
        debug(fprintf(stderr, "setting process limit to %lu\n", cfg.proc.lim));
        rlim.rlim_cur = rlim.rlim_max = cfg.proc.lim;
        if (0 > setrlimit(RLIMIT_NPROC, &rlim)) errExit("setrlimit");
    }

    int logfd = -1;

    if (log_path != NULL) {
        if (strcmp(log_path, "-") != 0) {
            logfd = open(log_path, O_CREAT|O_RDWR|O_APPEND, 0644);
            if (logfd == -1) err_Exit("open");
        } else  {
            logfd = dup(1);
        }
    }

    // duplicate socket to stdio
    if (cfg.in && 0 != dup2(sock, 0)) errExit("dup2");
    if (cfg.out && 1 != dup2(sock, 1)) errExit("dup2");
    if (cfg.err && 2 != dup2(sock, 2)) errExit("dup2");
    if (close(sock)) errExit("close");

    if (log_path != NULL) stdin_log(logfd); // #1

    debug(fprintf(stderr, "installing exit handler ...\n"));
    if (on_exit(cleanup, NULL)) errExit("on_exit"); // #1 maybe race condition?

    pid_t ppid = getppid();
    parse_config_file(&cfg);
    enter_jail(&cfg, logfd);
    exit(0); // jail exits normally
}

void stop_server(int sig) {
    debug(fprintf(stderr, "stopping server ...\n"));
    while (1);
}

int main(int argc, char **argv, char **envp) {

    signal(SIGUSR1, stop_server);

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    pid_t pid;
    struct sigaction sigact;
    int lsock, sock;

    struct config cfg = {
        .family = AF_INET6,
        .addr = {.ipv6 = in6addr_any},
        .port = 1024,
        .in = true, .out = true, .err = true,
        .cpu = {.set = false}, .mem = {.set = false}, .proc = {.set = false},
        .conn = 1,
        .fss = 262144
    };

    parse_args(argc, argv, &cfg);

    debug(fprintf(stderr, "checking that this is running as root ...\n"));
    if (geteuid() != 0) {puts("you must run this as root."); exit(1);}

    CTFUID = get_ctf_uid();
    cwd = get_current_dir_name();
    if (cwd == NULL) errExit("get_current_dir_name");

    // do not turn dead children into zombies
    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_flags = SA_NOCLDWAIT | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sigact, 0)) errExit("sigaction");

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
            write(sock, "too many connections from this ip.\n", 34);
            if (close(sock)) errExit("close");
            continue;
        }
        if (r == NOSPACE) {
            debug(fprintf(stderr, "dropped. no space in ip table.\n"));
            write(sock, "internal error. try again later.\n", 33);
            if (close(sock)) errExit("close");
            continue;
        }

        if ((pid = fork())) {
            if (pid == -1) decrement_connection(glob_ip); // fork failed.
            if (close(sock)) errExit("close");
            continue; // parent
        }

        // child
        if (close(lsock)) errExit("close");
        if (0 > setsid()) errExit("setsid");

        signal(SIGUSR1, SIG_IGN);

        handle_connection(cfg, sock);
    }
    return 0;
}
