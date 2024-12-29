#include <unistd.h>

/*
root shell to test how secure the jail is.

config:
:rootshell:rootshell_example:bof:120:/challenge:nolist:suid:copy:
*/

void main() {

    setuid(0);
    setgid(0);

    // launch privileged bash
    char *const args[] = {"/bin/bash", NULL};
    execve("/bin/bash", args, NULL);
}