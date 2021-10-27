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

#include "ws/ws.h"
#include "ws/utf8.h"

void onmessage(struct ws_frame_data *wfd, const unsigned char *msg, uint64_t size, int type) {
#ifndef disable_verbose
	printf("i receive a message: %s (size: %lu, type: %d), from: %s:%d/%d\n",
		msg, size, type, wfd->ip, wfd->port, wfd->sock);
#endif

	/**
	 * mimicks the same frame type received and re-send it again
	 *
	 * please note that we could just use a ws_sendframe_txt()
	 * or ws_sendframe_bin() here, but we're just being safe
	 * and re-sending the very same frame type and content
	 * again.
	 */

	//ws_sendframe(wfd->sock, (char *)msg, size, type);
}

int main(int argc, char **argv) {
	struct sockaddr_in serveraddr;

	if(argc != 3) {
		printf("usage: ./c <ip> <port>\n");
		return 0;
	}

	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(atoi(argv[2]));

	if(inet_pton(AF_INET, argv[1], &serveraddr.sin_addr) <= 0){
		logd("inet_pton error");
		abort();
	}

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		logd("WSAStartup failed!");
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
		logd("Could not create socket");
		abort();
	}

	int reuse = 1;
	/* Reuse previous address. */
	if (setsockopt(serversock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) < 0) {
		logd("setsockopt(SO_REUSEADDR) failed");
		abort();
	}

	if (connect(serversock, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
		logd("Failed to connect");
		return 0;
	}

	ws_frame_data_t *wfd = ws_establishconnection(serversock);

	/* Do handshake. */
	if (!do_handshake(wfd)) {
		goto closed;
	}

	if (!finish_handshake(wfd)) {
		goto closed;
	}

	/* Read next frame until client disconnects or an error occur. */
	char buf[4096] = {0};
	
	fprintf(stderr, "[%d]: wait for data to send ...\n", __LINE__);
	while (scanf("%s", buf) != EOF) {
		fprintf(stderr, "Buffer [%d]: %s\n", (int)strlen(buf), buf);
		ws_sendframe_txt(wfd->sock, buf);

		if(next_frame(wfd) >= 0) {
			onmessage(wfd, wfd->msg, wfd->frame_size, wfd->frame_type);
		}

		if (wfd->frame_type == WS_FR_OP_CLSE && !wfd->error) {
			/* Close event. */

			/*
			 * We only send a CLOSE frame once, if we're already
			 * in CLOSING state, there is no need to send.
			 */
			if (wfd->state != WS_STATE_CLOSING) {
				wfd->state = WS_STATE_CLOSING;

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
	logd("Closed...");
	if(wfd) free(wfd);

	return (0);
}
