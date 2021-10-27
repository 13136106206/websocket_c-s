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

#ifndef WS_H
#define WS_H
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
	#include "utf8.h"

	#include <stdbool.h>
	#include <stdint.h>
	#include <inttypes.h>

	/**
	 * @name Global configurations
	 */
	/**@{*/
	/**
	 * @brief Max clients connected simultaneously.
	 */
	#define MAX_CLIENTS    8

	/**
	 * @brief Max number of `ws_server` instances running
	 * at the same time.
	 */
	#define MAX_PORTS      16
	/**@}*/

	/**
	 * @name Key and message configurations.
	 */
	/**@{*/
	/**
	 * @brief Message buffer length.
	 */
	#define MESSAGE_LENGTH 2048
	/**
	 * @brief Maximum frame/message length.
	 */
	#define MAX_FRAME_LENGTH (16*1024*1024)
	/**
	 * @brief WebSocket key length.
	 */
	#define WS_KEY_LEN     24
	/**
	 * @brief Magic string length.
	 */
	#define WS_MS_LEN      36
	/**
	 * @brief Accept message response length.
	 */
	#define WS_KEYMS_LEN   (WS_KEY_LEN + WS_MS_LEN)
	/**
	 * @brief Magic string.
	 */
	#define MAGIC_STRING   "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	/**@}*/

	/**
	 * @name Handshake constants.
	 */
	/**@{*/
	/**
	 * @brief Alias for 'Sec-WebSocket-Key'.
	 */
	#define WS_HS_REQ      "Sec-WebSocket-Key"

	/**
	 * @brief Handshake accept message length.
	 */
	#define WS_HS_ACCLEN   130

	/**
	 * @brief Handshake accept message.
	 */
	#define WS_HS_ACCEPT                       \
		"HTTP/1.1 101 Switching Protocols\r\n" \
		"Upgrade: websocket\r\n"               \
		"Connection: Upgrade\r\n"              \
		"Sec-WebSocket-Accept: "
	/**@}*/

	/**
	 * @name Frame types.
	 */
	/**@{*/
	/**
	 * @brief Frame FIN.
	 */
	#define WS_FIN      128

	/**
	 * @brief Frame FIN shift
	 */
	#define WS_FIN_SHIFT  7

	/**
	 * @brief Continuation frame.
	 */
	#define WS_FR_OP_CONT 0

	/**
	 * @brief Text frame.
	 */
	#define WS_FR_OP_TXT  1

	/**
	 * @brief Binary frame.
	 */
	#define WS_FR_OP_BIN  2

	/**
	 * @brief Close frame.
	 */
	#define WS_FR_OP_CLSE 8

	/**
	 * @brief Ping frame.
	 */
	#define WS_FR_OP_PING 0x9

	/**
	 * @brief Pong frame.
	 */
	#define WS_FR_OP_PONG 0xA

	/**
	 * @brief Unsupported frame.
	 */
	#define WS_FR_OP_UNSUPPORTED 0xF
	/**@}*/

	/**
	 * @name Close codes
	 */
	/**@{*/
	/**
	 * @brief Normal close
	 */
	#define WS_CLSE_NORMAL  1000
	/**
	 * @brief Protocol error
	 */
	#define WS_CLSE_PROTERR 1002
	/**@}*/
	/**
	 * @brief Inconsistent message (invalid utf-8)
	 */
	#define WS_CLSE_INVUTF8 1007

	/**
	 * @name Connection states
	 */
	/**@{*/
	/**
	 * @brief Connection not established yet.
	 */
	#define WS_STATE_CONNECTING 0
	/**
	 * @brief Communicating.
	 */
	#define WS_STATE_OPEN       1
	/**
	 * @brief Closing state.
	 */
	#define WS_STATE_CLOSING    2
	/**
	 * @brief Closed.
	 */
	#define WS_STATE_CLOSED     3
	/**@}*/

	/**
	 * @name Timeout util
	 */
	/**@{*/
	/**
	 * @brief Nanoseconds macro converter
	 */
	#define MS_TO_NS(x) ((x)*1000000)
	/**
	 * @brief Timeout in milliseconds.
	 */
	#define TIMEOUT_MS (500)
	/**@}*/

	/**
	 * @name Handshake constants.
	 */
	/**@{*/
	/**
	 * @brief Debug
	 */
	#ifdef VERBOSE_MODE
	#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
	#else
	#define DEBUG(...)
	#endif
	/**@}*/

	#define CLI_SOCK(sock) (sock)
	#define SEND(fd,buf,len) send_all((fd), (buf), (len), MSG_NOSIGNAL)
	#define RECV(fd,buf,len) recv((fd), (buf), (len), 0)

	typedef struct ws_frame_data {
		int sock;
		int port;
		char ip[16];
		int state;

		struct ws_events *evs;

		bool masked;
		unsigned char mask[4];
		/**
		 * @brief Frame read.
		 */
		unsigned char frm[MESSAGE_LENGTH];
		/**
		 * @brief Processed message at the moment.
		 */
		unsigned char *msg;
		/**
		 * @brief Control frame payload
		 */
		unsigned char msg_ctrl[125];
		/**
		 * @brief Current byte position.
		 */
		size_t cur_pos;
		/**
		 * @brief Amount of read bytes.
		 */
		size_t amt_read;
		/**
		 * @brief Frame type, like text or binary.
		 */
		int frame_type;
		/**
		 * @brief Frame size.
		 */
		uint64_t frame_size;
		/**
		 * @brief Error flag, set when a read was not possible.
		 */
		int error;
	} ws_frame_data_t;

	/* Forward declarations. */
	extern int get_handshake_accept(char *wsKey, unsigned char **dest);
	extern int get_handshake_response(char *hsrequest, char **hsresponse);
	extern int ws_close_client(int fd);
	extern int ws_socket(struct ws_events *evs, uint16_t port);

	extern void close_socket(int fd);
	extern ssize_t send_all(int sockfd, const void *buf, size_t len, int flags);
	extern void *close_timeout(void *p);
	extern int ws_sendframe(int fd, const char *msg, uint64_t size, int type);
	extern int ws_sendframe_txt(int fd, const char *msg);
	extern int ws_sendframe_bin(int fd, const char *msg, uint64_t size);
	extern int ws_close_client(int fd);
	extern int is_control_frame(int frame);
	extern struct ws_frame_data *ws_establishconnection(int socket);
	extern bool do_handshake(struct ws_frame_data *wfd);
	extern bool return_handshake(struct ws_frame_data *wfd);
	extern bool finish_handshake(struct ws_frame_data *wfd);
	extern int do_close(struct ws_frame_data *wfd, int close_code);
	extern int do_pong(struct ws_frame_data *wfd, uint64_t frame_size);
	extern int next_byte(struct ws_frame_data *wfd);
	extern int skip_frame(struct ws_frame_data *wfd, uint64_t frame_size);
	extern int read_frame(struct ws_frame_data *wfd, int opcode, unsigned char **buf, uint64_t *frame_length, uint64_t *frame_size, uint64_t *msg_idx, uint8_t *masks, int is_fin);
	extern int next_frame(struct ws_frame_data *wfd);


#ifndef logd
	#include "stdarg.h"
	static inline void logdd(const char *file, const char *function, int line, const char *format, ...);
	static inline void logdd(const char *file, const char *function, int line, const char *format, ...) {
		va_list ap;
		char message[4096] = {0};

		va_start(ap, format);
		int len = vsnprintf(message, sizeof(message), format, ap);
		message[sizeof(message) - 1] = 0;
		va_end(ap);

		if(len > 0 && (size_t)len < sizeof(message) - 1 && message[len - 1] == '\n') {
			message[len - 1] = 0;
		}

		time_t t = time(NULL);
		char timestr[4096] = {0};
		strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&t));
		fprintf(stderr, "[%s] %s:%s [%d] %s\n", timestr, file, function, line, message);
	}

	#define FFL __FILE__, __FUNCTION__, __LINE__
	#define logd(...)  logdd(__FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#endif

#ifndef safe_free
	#define safe_free(x) if(x) free(x); x = NULL
#endif

#endif /* WS_H */
