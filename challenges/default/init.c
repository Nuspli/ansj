#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <grp.h>

/*
default challenge binary to show what's possible.
let's say we want to drop the user in an unprivileged bash shell.
we also want there to be an suid binary (catflag) that can be used to read the flag.
we don't want anything else in the challenge directory.
we also want the flag to be in /flag, not in the challenge directory and only readable by root.

config:
:bash:default:init:120:/challenge:list:suid:copy:
-> challenge key: bash
-> challenge directory name inside the challenges directory: default
-> name of the file to be executed on a connection: init
-> timeout in seconds: 120
-> directory where the challenge files will be placed inside the jail: /challenge
-> do make key appear in the help text (list)
-> do make init an suid binary (suid)
-> do copy the files in this directory into the jail instead of mounting them readonly (copy)

what this init binary does:
- temporarily elevates privilages to root
- copies flag file to /flag.
- changes flag permissions to only be readable by root.
- changes ownership and sets suid bit of the second binary (catflag).
- deletes anything but catflag from the challenge directory.
- launches an unprivileged bash shell.

*/

int main(int argc, char **argv) {

    int ctfuid = getuid();
    int ctfgid = getgid();

    // privileges are dropped to ctf user right now. to make any changes to /flag for example, we need to be root
    setuid(0);
    setgid(0);

    // copy flag to /flag
    int src_fd = open("flag", O_RDONLY);

    struct stat st;
    fstat(src_fd, &st);

    int dst_fd = open("/flag", O_WRONLY | O_CREAT, st.st_mode);
    sendfile(dst_fd, src_fd, NULL, st.st_size);

    close(src_fd);
    close(dst_fd);

    // changing ownership of /flag is not necessary, as it's already owned by root (we just created it)
    // change permissions of flag to only be readable by root
    chmod("/flag", 0400);

    // change ownership of catflag to root
    chown("catflag", 0, 0);
    // set suid bit on catflag
    chmod("catflag", 04755);

    // delete everything but catflag from the /challenge directory
    unlink("init.c");
    unlink("init");
    unlink("catflag.c");
    unlink("flag");

    // drop to ctf user again
    setgroups(0, NULL);
    setgid(ctfgid);
    setuid(ctfuid);

    // launch bash
    char *const args[] = {"/bin/bash", NULL};
    execve("/bin/bash", args, NULL);
}