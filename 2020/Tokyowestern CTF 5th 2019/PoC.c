/*
 *  h-c0n 2020 PoC
 *
 *  gcc PoC.c
 *
 */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
	FILE *fp;
	
	/* Open a file, observe it ended up at previous location. */
	if (!(fp = fopen("/dev/null", "w"))) {
		perror("fopen");
		return -1;
	}
	
	fp->_flags = 0xfbad2887 | 0x1000;
	fp->_IO_read_ptr = 0; // field 1º
	fp->_IO_read_end = 0; // field 2º
	fp->_IO_read_base = 0; // field 3º
	fp->_IO_write_base = (unsigned long)fp + 0x88; // field 4º, at+0x20 leak 8 bytes in the _IO_2_1_stdout_ structure
	fp->_IO_write_ptr = (unsigned long)fp + 0x88 + 0x8; // field 5º, at+0x28
	fp->_fileno = 1; // field 14º, at+0x70

	return 0;
}

