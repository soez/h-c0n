/*
 *
 *  Qurtuba CTF 2017
 *  newbies - by @javierprtd
 *
 *  gcc -no-pie newbies.c -o newbies -fno-stack-protector
 *  socat tcp-listen:31337,reuseaddr,fork exec:"timeout 60 /home/noname/jail/newbies",chroot=/home/noname/jail,su-d=noname
 *
 */

#include <stdio.h>
#include <stdlib.h>

int vuln() {
	char buf[256] = {0};
	puts("Try to overflow me ;)");
	scanf("%256s", buf);

	return 0;
}

int main(int argc, char *argv[]) {
	setvbuf(stdin, 0, _IONBF, 0);
  	setvbuf(stdout, 0, _IONBF, 0);	

	vuln();

	return 0;
}

