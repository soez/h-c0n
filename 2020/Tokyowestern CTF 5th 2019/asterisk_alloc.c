#define TRUE 1

unsigned char *ptr_r, *ptr_m, *ptr_c;

// Base PIE + 0xA1A
void initialize() {
	setbuf(stdin, 0);
	setbuf(stdout, 0);
}

// Base PIE + 0xA49
int print_menu() {
	puts("=================================");
	puts("1. malloc");
	puts("2. calloc");
	puts("3. realloc");
	puts("4. free");
	puts("5. exit");
	puts("=================================");
	
	return 0;
}

// Base PIE + 0xAA4
unsigned int call_malloc() {
	size_t size;

	if (!ptr_m) {
		printf("Size: ");
		__isoc99_scanf("%ld", &size);
		getchar();
		printf("Data: %d", size);
		ptr_m = malloc(size);
		read(0, ptr_m, size);
	}

	return 0;
}

// Base PIE + 0xB4D
unsigned int call_calloc() {
	size_t size;

	if (!ptr_c) {
		printf("Size: ");
		__isoc99_scanf("%ld", &size);
		getchar();
		ptr_c = calloc(1, size);
		printf("Data: %d", size);
		read(0, ptr_c, size);
	}

	return 0;
}

// Base PIE + 0xBFB
unsigned int call_realloc() {
	size_t size;

	printf("Size: ");
	__isoc99_scanf("%ld", &size);
	getchar();
	ptr_r = realloc(ptr_r, size);
	printf("Data: %d", size);
	read(0, ptr_r, size);

	return 0;
}

// Base PIE + 0xCA3
unsigned int call_free() {
	char m;

	printf("Which: ");
	__isoc99_scanf("%c", &m);
	getchar();
	switch (m) {
		case 'm': free(ptr_m); break;
		case 'c': free(ptr_c); break;
		case 'r': free(ptr_r); break;
		default: puts("Invalid choice"); break;
	}

	return 0;
}

// Base PIE + 0xD56
int main(int argc, const char **argv) {
	int m;

	initialize();
	while (TRUE) {
		print_menu();
		printf("Your choice: ");
		__isoc99_scanf("%d", &m);
		getchar();
		switch (m) {
			case 1: call_malloc(); break;
			case 2: call_calloc(); break;
			case 3: call_realloc(); break;
			case 4: call_free(); break;
			case 5: _exit(0);
			default: puts("Invalid choice"); break;
		}
	}

	return 0;
}
