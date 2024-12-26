#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

#include <sys/syscall.h>
#include <sys/mount.h>
#include <dirent.h>
#include <limits.h>
#include <sched.h>
#include <grp.h>
#include <pwd.h>

struct linux_dirent64 {
    unsigned long long d_ino;
    unsigned long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

//#define DEBUG

#ifdef DEBUG
    /* code inside debug() will be executed (DEBUG is defined). */
    #define debug(code) code
#else
    /* code inside debug() will be ignored (DEBUG is not defined). */
    #define debug(code)
#endif
#define errExit(msg, code) do {perror(msg); exit(code);} while (0)

#define CRIT_EXIT 42

int MAXTIME = 60;

/* closes all open file descriptors except for stdin, stdout, stderr. */
void close_open_fds() {

    int dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    if (dir == -1) {perror("open"); return;}

    char buf[0x1000];

    while (1) {
        int nread = syscall(SYS_getdents64, dir, buf, sizeof(buf));
        if (nread == -1) {perror("getdents64"); break;}
        if (nread == 0) break; // end of directory

        for (int bpos = 0; bpos < nread;) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + bpos);
            bpos += d->d_reclen;

            int fd = atoi(d->d_name);
            if (fd == dir || fd <= 2) continue; // skip self (dir) and standard IO (0, 1, 2)
            close(fd);
        }
    }
    close(dir);
}


void delete_directory(const char *path) {

    struct dirent *entry;
    DIR *dir = opendir(path);

    if (dir == NULL) {
        perror("opendir");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(full_path, &st) == -1) {
            perror("lstat");
            continue;
        }

        // unmount any mounted filesystems
        if (umount2(full_path, MNT_DETACH) == 0) {
            debug(printf("... unmounted: %s\n", full_path));
        }

        if (S_ISDIR(st.st_mode)) {
            // Recursively delete subdirectory
            delete_directory(full_path);
            debug(printf("... removing directory %s.\n", full_path));
            rmdir(full_path);

        } else {
            // Delete file or symlink
            debug(printf("... removing file %s.\n", full_path));
            if (unlink(full_path) == -1) {
                perror("unlink");
            }
        }
    }

    closedir(dir);
}

int get_ctf_uid() {
    struct passwd *pw = getpwnam("ctf");
    if (pw == NULL) errExit("getpwnam", 1);
    return pw->pw_uid;
}

void timeout_handler(int sig) {
    puts("timeout!");
    exit(EXIT_FAILURE);
}

/*
./config:
:key:dirname_in_challenges:file_in_dir_to_exec:timeout_in_seconds:flag_path_in_jail:flag:challenge_file_dir_path_in_jail:nolist:
example:
:bash:default:bash:120:/flag:flag{default}:/challenge:

./challenges/
    default/
        bash
    chall2/
        chall2
        extrafile
*/

// sudo ynetd -p 31338 -se y -sh n ./challenge_hub

int main(int argc, char **argv, char **envp) {

    // ctf user should already exist
    int CTFUID = get_ctf_uid();

    char *cwd = get_current_dir_name();
    if (cwd == NULL) errExit("get_current_dir_name", 1);

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("enter the challenge key: ");
    char key[0x100];

    signal(SIGALRM, timeout_handler);
    alarm(5);
    fscanf(stdin, "%255s", key);
    alarm(0);

    FILE *config_fd = fopen("./config", "r");
    if (config_fd == NULL) errExit("fopen", 1);

    int read;
    size_t len = 0;
    char *line = NULL;

    char *dirname_in_challenges = NULL;
    char *file_in_dir_to_exec = NULL;
    char *timeout = NULL;
    char *flag_path_in_jail = NULL;
    char *flag = NULL;
    char *challenge_file_dir_path_in_jail = NULL;
    bool display = false;
    bool found = false;

    if (strcmp(key, "help") == 0) {
        puts("this service is probably used to host ctf challenges.");
        puts("in order to access a challenge, you need to know the key.");
        puts("if it hasn't been specified or doesn't work, contact the organizers.\n");
        puts("publically available keys:");
        display = true;
    }

    while ((read = getline(&line, &len, config_fd)) != -1) {
        char *keychall = strtok(line, ":");
        if (display) puts(keychall);
        dirname_in_challenges = strtok(NULL, ":");
        file_in_dir_to_exec = strtok(NULL, ":");
        timeout = strtok(NULL, ":");
        flag_path_in_jail = strtok(NULL, ":");
        flag = strtok(NULL, ":");
        challenge_file_dir_path_in_jail = strtok(NULL, ":");
        if (strcmp(keychall, key) == 0) {
            MAXTIME = atoi(timeout);
            found = true;
            break;
        }
    }

    fclose(config_fd);

    if (dirname_in_challenges == NULL || file_in_dir_to_exec == NULL || timeout == NULL || flag_path_in_jail == NULL || flag == NULL || challenge_file_dir_path_in_jail == NULL) {
        puts("error reading config file.");
        exit(EXIT_FAILURE);
    }

    if (!found) {
        if (!display) puts("challenge not found. try 'help' if you don't know the key.");
        exit(EXIT_FAILURE);
    }

    char new_root[] = "/tmp/jail-XXXXXX";
    char old_root[PATH_MAX];

    char old_challenge_dir_path[PATH_MAX] = {0};
    strcpy(old_challenge_dir_path, "/old");
    strcat(old_challenge_dir_path, cwd);
    strcat(old_challenge_dir_path, "/challenges/");
    strcat(old_challenge_dir_path, dirname_in_challenges);

    char old_file_to_exec[PATH_MAX] = {0};
    strcpy(old_file_to_exec, old_challenge_dir_path);
    strcat(old_file_to_exec, "/");
    strcat(old_file_to_exec, file_in_dir_to_exec);

    char new_challenge_dir_path[PATH_MAX] = {0};
    strcpy(new_challenge_dir_path, challenge_file_dir_path_in_jail);

    char new_file_to_exec[PATH_MAX] = {0};
    strcpy(new_file_to_exec, new_challenge_dir_path);
    strcat(new_file_to_exec, "/");
    strcat(new_file_to_exec, file_in_dir_to_exec);

    debug(puts("checking that this is running as root ..."));
    if (geteuid() != 0) errExit("you must run this as root.", 1);

    debug(puts("splitting off into our own mount namespace ..."));
    if (unshare(CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET) == -1) errExit("unshare", 1);

    debug(puts("creating jail structure ..."));
    debug(puts("... creating jail root ..."));
    if (mkdtemp(new_root) == NULL) errExit("mkdtemp", 1);
    debug(printf("... ... created jail root at `%s`.\n", new_root));

    debug(puts("... changing the old / to a private mount so that pivot_root succeeds later."));
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) errExit("mount", 1);

    debug(puts("... bind-mounting the new root over itself so that it becomes a 'mount point' for pivot_root() later."));
    if (mount(new_root, new_root, NULL, MS_BIND, NULL) == -1) errExit("mount", 1);

    debug(puts("... creating a directory in which pivot_root will put the old root filesystem."));
    snprintf(old_root, sizeof(old_root), "%s/old", new_root);
    if (mkdir(old_root, 0777) == -1) errExit("mkdir", 1);

    debug(puts("... obtaining a file descriptor for the old root directory ..."));
    int cleanup_dirfd = open("/", O_DIRECTORY);
    debug(printf("... ... obtained file descriptor %d for the old root directory.\n", cleanup_dirfd));

    // after this, / will refer to /tmp/jail-XXXXXX, and /old will refer to the old root filesystem
    debug(puts("... pivoting the root filesystem!"));
    if (syscall(SYS_pivot_root, new_root, old_root) == -1) {
        // if pivot root fails we would run the risk of the cleanup process deleting the real root filesystem.
        errExit("CRITICAL ERROR: pivot_root", CRIT_EXIT);
    }

    char *dirs[] = {"/bin", "/lib", "/lib64", "/usr", "/etc", "/var", "/dev", "/sbin", NULL};
    for (char **dir = dirs; *dir; dir++) {
        char *path = *dir;
        char old_path[PATH_MAX];
        snprintf(old_path, sizeof(old_path), "/old%s", path);

        debug(printf("... bind-mounting (read-only) %s for you into %s in the jail.\n", old_path, path));
        if (mkdir(path, 0755) == -1) errExit("mkdir", CRIT_EXIT);
        if (mount(old_path, path, NULL, MS_BIND|MS_RDONLY, NULL) == -1) errExit("mount", CRIT_EXIT);
        if (mount(NULL, path, NULL, MS_REMOUNT|MS_BIND|MS_RDONLY, NULL) == -1) errExit("mount", CRIT_EXIT);
    }

    // mount the challenge files into the new challenge directory
    // make file to exec suid root to allow further setup
    debug(printf("... making %s suid root.\n", old_file_to_exec));
    if (chown(old_file_to_exec, 0, 0) == -1) errExit("chown", CRIT_EXIT);
    if (chmod(old_file_to_exec, 04755) == -1) errExit("chmod", CRIT_EXIT);

    debug(printf("... bind-mounting (read-only) %s for you into %s in the jail.\n", old_challenge_dir_path, new_challenge_dir_path));
    if (mkdir("/challenge", 0755) == -1) errExit("mkdir", CRIT_EXIT);
    if (open(new_challenge_dir_path, O_CREAT) == -1) errExit("open", CRIT_EXIT);
    if (mount(old_challenge_dir_path, new_challenge_dir_path, NULL, MS_BIND|MS_RDONLY, NULL) == -1) errExit("mount", CRIT_EXIT);
    if (mount(NULL, new_challenge_dir_path, NULL, MS_REMOUNT|MS_BIND|MS_RDONLY, NULL) == -1) errExit("mount", CRIT_EXIT);

    // make home directory for ctf user.
    debug(puts("... creating home directory for ctf user."));
    if (mkdir("/home", 0755) == -1) errExit("mkdir", CRIT_EXIT);
    if (mkdir("/home/ctf", 0750) == -1) errExit("mkdir", CRIT_EXIT);
    if (chown("/home/ctf", CTFUID, CTFUID) == -1) errExit("chown", CRIT_EXIT);

    // put flag in the jail
    int flag_fd = open(flag_path_in_jail, O_WRONLY | O_CREAT);
    write(flag_fd, flag, strlen(flag));
    close(flag_fd);
    // if you need to change the permissions, do that in a setup script

    // remove the old root mount
    debug(puts("... unmounting old root directory."));
    if (umount2("/old", MNT_DETACH) == -1) errExit("umount2", CRIT_EXIT); // not safe until real root is unmounted
    if (rmdir("/old") == -1) errExit("rmdir", 1);

    debug(puts("moving the current working directory into the jail."));
    if (chdir("/home/ctf") != 0) errExit("chdir", 1);

    chmod("/", 0755);

    debug(puts("starting new init process ..."));
    pid_t init_pid = fork();
    debug(printf("... forked with init_pid %d\n", init_pid));
    if (init_pid == -1) errExit("fork", 1);
    if (init_pid != 0) {wait(NULL); return 0;} // keep the (useless) parent around

    // continue as init from here on

    debug(puts("bind-mounting fresh /proc into jail."));
    if (mkdir("/proc", 0755) == -1) errExit("mkdir", 1);
    if (mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) != 0) errExit("mount", 1);
    if (mount(NULL, "/proc", NULL, MS_REMOUNT|MS_BIND|MS_RDONLY, NULL) != 0) errExit("mount", 1);

    printf("your instance will die in %d seconds.\n", MAXTIME);
    
    debug(puts("forking off challenge process ..."));
    pid_t p = fork();
    debug(printf("... forked with pid %d\n", p));
    if (p == -1) errExit("fork", 1);
    
    if (p == 0) {
        // close all open file descriptors except for stdin, stdout, stderr
        close_open_fds();

        // drop all privileges
        debug(printf("... dropping privileges.\n"));
        setgroups(0, NULL);
        setgid(CTFUID);
        setuid(CTFUID);

        debug(puts("... launching challenge ...\n"));
        char *const args[] = {new_file_to_exec, NULL};
        if (execve(new_file_to_exec, args, NULL) == -1) errExit("execve", 1);
        
    } else {

        int status;
        int t = 0;
        while (waitpid(p, &status, WNOHANG) == 0) {
            if (t >= MAXTIME) {puts("timeout!"); break;}
            sleep(1);
            t++;
        }
        debug(printf("challenge exited with status %d\n", WEXITSTATUS(status)));

        debug(puts("... cleaning up the jail directory."));

        debug(puts("... removing files."));

        chdir("/"); // this is /tmp/jail-XXXXXX, not the real root
        delete_directory(".");

        debug(puts("... removing jail directory."));
        char *rel_pathname = (char *)new_root + 1;
        debug(printf("... removing jail directory at %s relative to dirfd %d\n", rel_pathname, cleanup_dirfd));
        if (unlinkat(cleanup_dirfd, rel_pathname, AT_REMOVEDIR) == -1) errExit("unlinkat", 1);
    }
    close(cleanup_dirfd);
    debug(puts("... exiting."));
    return 0;
}
