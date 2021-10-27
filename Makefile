all:
	gcc ws/base64.c ws/base64.h ws/handshake.c ws/sha1.c ws/sha1.h ws/utf8.c ws/utf8.h ws/ws.h ws/ws.c s.c -o s
	gcc ws/base64.c ws/base64.h ws/handshake.c ws/sha1.c ws/sha1.h ws/utf8.c ws/utf8.h ws/ws.h ws/ws.c c.c -o c

install: all
