import socket

target = "127.0.0.1"   # or 192.168.4.105
port = 8080

for i in range(2000):
    try:
        s = socket.socket()
        s.connect((target, port))
        s.send(b"GET / HTTP/1.1\r\n\r\n")
        s.close()
    except:
        pass