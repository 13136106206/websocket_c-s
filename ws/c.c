/*
 * Copyright (C) 2016-2021  Davidson Francis <davidsondfgl@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* clang-format off */
#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef int socklen_t;
#endif
/* clang-format on */

/* Windows and macOS seems to not have MSG_NOSIGNAL */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#include <unistd.h>

#include "ws.h"
#include "utf8.h"

void onopen(int fd) {
	char *cli;
	cli = ws_getaddress(fd);
#ifndef disable_verbose
	printf("connection opened, client: %d | addr: %s\n", fd, cli);
#endif
	free(cli);
}

void onclose(int fd) {
	char *cli;
	cli = ws_getaddress(fd);
#ifndef disable_verbose
	printf("connection closed, client: %d | addr: %s\n", fd, cli);
#endif
	free(cli);
}

void onmessage(int fd, const unsigned char *msg, uint64_t size, int type) {
	char *cli;
	cli = ws_getaddress(fd);
#ifndef disable_verbose
	printf("i receive a message: %s (size: %lu, type: %d), from: %s/%d\n",
		msg, size, type, cli, fd);
#endif
	free(cli);

	/**
	 * mimicks the same frame type received and re-send it again
	 *
	 * please note that we could just use a ws_sendframe_txt()
	 * or ws_sendframe_bin() here, but we're just being safe
	 * and re-sending the very same frame type and content
	 * again.
	 */
	ws_sendframe(fd, (char *)msg, size, true, type);
}

bool do_http_get(ws_frame_data_t *wfd) {
	char buf[4096] = {0};
	sprintf(buf,
		"GET / HTTP/1.1\r\n"
		"Host: %s:%d\r\n"
		"Connection: Upgrade\r\n"
		"Pragma: no-cache\r\n"
		"Cache-Control: no-cache\r\n"
		"User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\n"
		"Upgrade: websocket\r\n"
		"Origin: file://\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"Accept-Encoding: gzip, deflate\r\n"
		"Accept-Language: zh-CN,zh;q=0.9\r\n"
		"Sec-WebSocket-Key: 7QPh6Vcx0p4UK7OI9MCYAw==\r\n"
		"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n",
	wfd->ws_c->ip, wfd->ws_c->port);

	int output = SEND(wfd->sock, buf, strlen(buf));

	if (output) {
		panic("Failed to do_http_get");
		return false;
	}

	char *p;        /* Last request line pointer.  */
	ssize_t n;      /* Read/Write bytes.           */

	/* Read the very first client message. */
	if ((n = RECV(wfd->sock, wfd->frm, sizeof(wfd->frm) - 1)) < 0) {
		return (-1);
	}

	fprintf(stderr, "Got handshake: \n"
		"------------------------------------\n"
		"%s"
		"------------------------------------\n",
		(char *)wfd->frm);

	/* Advance our pointers before the first next_byte(). */
	p = strstr((const char *)wfd->frm, "\r\n\r\n");
	if (p == NULL) {
		fprintf(stderr, "An empty line with \\r\\n was expected!\n");
		return (-1);
	}

	wfd->amt_read = n;
	wfd->cur_pos  = (size_t)((ptrdiff_t)(p - (char *)wfd->frm)) + 4;

	return true;
}

int ws_connect(struct ws_events *evs, struct sockaddr_in *serveraddr) {
	/* Checks if the event list is a valid pointer. */
	if (evs == NULL) {
		panic("Invalid event list!");
		abort();
	}

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		panic("WSAStartup failed!");
		abort();
	}

	/**
	 * Sets stdout to be non-buffered.
	 *
	 * According to the docs from MSDN (setvbuf page), Windows do not
	 * really supports line buffering but full-buffering instead.
	 *
	 * Quote from the docs:
	 * "... _IOLBF For some systems, this provides line buffering.
	 *  However, for Win32, the behavior is the same as _IOFBF"
	 */
	setvbuf(stdout, NULL, _IONBF, 0);
#endif

	int serversock = socket(AF_INET, SOCK_STREAM, 0);

	if (serversock < 0) {
		panic("Could not create socket");
		abort();
	}

	int reuse = 1;
	/* Reuse previous address. */
	if (setsockopt(serversock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) < 0) {
		panic("setsockopt(SO_REUSEADDR) failed");
		abort();
	}

	if (connect(serversock, (struct sockaddr *)serveraddr, sizeof(*serveraddr)) < 0) {
		panic("Failed to connect");
		return 0;
	}

	struct ws_connection *ws_c = calloc(sizeof(*ws_c), 1);
	sprintf(ws_c->ip, "%s", inet_ntoa(serveraddr->sin_addr));
	ws_c->sock = serversock;
	ws_c->port = ntohs(serveraddr->sin_port);
	ws_c->state = WS_STATE_CONNECTING;

	ws_frame_data_t *wfd = calloc(sizeof(*wfd), 1); /* WebSocket frame data.   */

	wfd->sock = ws_c->sock;
	wfd->ws_c = ws_c;
	wfd->evs = evs;

	/* Do handshake. */
	if (do_http_get(wfd) < 0) {
		if (ws_c->state != WS_STATE_OPEN) {
			if(wfd) free(wfd);
			close_socket(ws_c->sock);
			if(ws_c) free(ws_c);
		}

		return 0;
	}

	/* Change state. */
	ws_c->state = WS_STATE_OPEN;

	/* Read next frame until client disconnects or an error occur. */
	char buf[4096] = {0};
	
	fprintf(stderr, "[%d]: wait for data to send ...\n", __LINE__);
	while (scanf("%s", buf) != EOF) {
		fprintf(stderr, "Buffer [%d]: %s\n", (int)strlen(buf), buf);
		ws_sendframe_txt(wfd->sock, buf, false);

		if(next_frame(wfd) >= 0) {
			char *cli;
			cli = ws_getaddress(wfd->sock);
#ifndef disable_verbose
			printf("i receive a message: %s (size: %lu, type: %d), from: %s/%d\n",
				wfd->msg, wfd->frame_size, wfd->frame_type, cli, wfd->sock);
#endif
			free(cli);
		}

		if (wfd->frame_type == WS_FR_OP_CLSE && !wfd->error) {
			/* Close event. */

			/*
			 * We only send a CLOSE frame once, if we're already
			 * in CLOSING state, there is no need to send.
			 */
			if (wfd->ws_c->state != WS_STATE_CLOSING) {
				wfd->ws_c->state = WS_STATE_CLOSING;

				/* We only send a close frameSend close frame */
				do_close(wfd, -1);
				goto closed;
			}

			free(wfd->msg);
			break;
		}

		free(wfd->msg);
	}

closed:
	panic("Closed...");
	if(wfd) free(wfd);
	if(ws_c) free(ws_c);
	return (0);
}

int main(int argc, char **argv) {
	struct ws_events evs;
	evs.onopen    = &onopen;
	evs.onclose   = &onclose;
	evs.onmessage = &onmessage;
    
	struct sockaddr_in serveraddr;

	if(argc != 3) {
		printf("usage: ./c <ip> <port>\n");
		return 0;
	}

	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(atoi(argv[2]));

	if(inet_pton(AF_INET, argv[1], &serveraddr.sin_addr) <= 0){
		panic("inet_pton error");
		abort();
	}

	ws_connect(&evs, &serveraddr);

	return (0);
}
