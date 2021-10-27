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

static void *ws_establishconnection(ws_connection_t *ws_c, struct ws_events *evs) {
	ws_frame_data_t *wfd = calloc(sizeof(*wfd), 1); /* WebSocket frame data.   */

	int sock             = ws_c->sock;
	int p_index          = ws_c->port;

	wfd->sock = sock;
	wfd->ws_c = ws_c;
	wfd->evs = evs;

	/* Do handshake. */
	if (do_handshake(wfd) < 0) {
		goto closed;
	}

	/* Change state. */
	ws_c->state = WS_STATE_OPEN;

closed:
	if (ws_c->state != WS_STATE_OPEN) {
		if(wfd) free(wfd);
		/* Removes client socket from socks list. */
		ws_c->sock = -1;
		ws_c->state       = WS_STATE_CLOSED;
		close_socket(sock);
	}

	return (wfd);
}

static void *ws_accept(int serversock) {
	int clientsock;
	struct sockaddr_in sa;
	int new_sock;
	int i;

	int sl = sizeof(struct sockaddr_in);

	/* Accept. */
	clientsock = accept(serversock, (struct sockaddr *)&sa, (socklen_t *)&sl);

	if (new_sock < 0) {
		panic("Error on accepting connections..");
		abort();
	}

	if (getpeername(clientsock, (struct sockaddr *)&sa, &sl)) {
		panic("Error on getpeername..");
		abort();
	}

	struct ws_connection *ws_c = calloc(sizeof(*ws_c), 1);
	sprintf(ws_c->ip, "%s", inet_ntoa(sa.sin_addr));
	ws_c->sock = clientsock;
	ws_c->port        = ntohs(sa.sin_port);
	ws_c->state       = WS_STATE_CONNECTING;

	return ws_c;
}

int ws_socket(struct ws_events *evs, uint16_t port) {
	int serversock;            /* Accept thread data.    */
	struct sockaddr_in server;     /* Server.                */
	int reuse;                     /* Socket option.         */

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

	/* Create socket. */
	serversock = socket(AF_INET, SOCK_STREAM, 0);

	if (serversock < 0) {
		panic("Could not create socket");
		abort();
	}

	/* Reuse previous address. */
	reuse = 1;
	if (setsockopt(serversock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) < 0) {
		panic("setsockopt(SO_REUSEADDR) failed");
		abort();
	}

	/* Prepare the sockaddr_in structure. */
	server.sin_family      = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port        = htons(port);

	/* Bind. */
	if (bind(serversock, (struct sockaddr *)&server, sizeof(server)) < 0) {
		panic("Bind failed");
		abort();
	}

	/* Listen. */
	listen(serversock, 3);

	/* Wait for incoming connections. */
	printf("Waiting for incoming connections...\n");

ACCEPT:{}
	/* Accept connections. */
	ws_connection_t *ws_c = ws_accept(serversock);

	if(!ws_c) {
		panic("Error client fd");
		abort();
	}

	ws_frame_data_t *wfd = ws_establishconnection(ws_c, evs);
	if(!wfd) {
		panic("Failed to ws_establishconnection, accept the next");
		goto ACCEPT;
	}

	/* Read next frame until client disconnects or an error occur. */
	while (next_frame(wfd) >= 0)	{
		/* Text/binary event. */
		if ((wfd->frame_type == WS_FR_OP_TXT || wfd->frame_type == WS_FR_OP_BIN) && !wfd->error) {
			wfd->evs->onmessage(wfd->sock, wfd->msg, wfd->frame_size, wfd->frame_type);

		} else if (wfd->frame_type == WS_FR_OP_CLSE && !wfd->error) {
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

int main(int argc, char **argv) {
	struct ws_events evs;
	evs.onopen    = &onopen;
	evs.onclose   = &onclose;
	evs.onmessage = &onmessage;

	if(argc == 1) {
		ws_socket(&evs, 8080);

	} else {
		ws_socket(&evs, atoi(argv[1]));
	}

	return (0);
}
