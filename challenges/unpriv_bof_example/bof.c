#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>
#include<sys/sendfile.h>

/*
classic buffer overflow example. if you don't need an suid setup, this is much simpler (and faster).

config:
:bof:unpriv_bof_example:bof:30:/challenge:nolist:nosuid:nocopy:
*/

int main() {

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    char buf[100];

    printf("enter some text: ");

    int r = read(0, buf, 0x100);

    if (r > 100) {
        puts("buffer overflow detected!");
        printf("here is your flag: ");
        sendfile(1, open("flag.txt", 0), NULL, 0x100);
        exit(0);
    } else {
        puts("no buffer overflow detected.");
    }

    return 0;
}