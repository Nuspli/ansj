#include<unistd.h>
#include<sys/sendfile.h>
#include<fcntl.h>

int main() {
    sendfile(1, open("/flag", 0), NULL, 0x100);
}