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

ssize_t send_all(int sockfd, const void *buf, size_t len, int flags) {
	const char *p;
	ssize_t ret;
	p = buf;
	ssize_t r = (ssize_t)len;

	while (len) {
		ret = send(sockfd, p, len, flags);

		if (ret == -1) {
			return (-1);
		}

		p += ret;
		len -= ret;
	}

	return r;
}

int ws_sendframe(int fd, const char *msg, uint64_t size, int type) {
	unsigned char *response; /* Response data.     */
	unsigned char frame[10]; /* Frame.             */
	uint8_t idx_first_rData; /* Index data.        */
	uint64_t length;         /* Message length.    */
	int idx_response;        /* Index response.    */
	ssize_t output;          /* Bytes sent.        */
	ssize_t send_ret;        /* Ret send function  */
	int sock;                /* File Descript.     */
	uint64_t i;              /* Loop index.        */
	int cur_port_index;      /* Current port index */

	frame[0] = (WS_FIN | type);
	length   = (uint64_t)size;

	/* Split the size between octets. */
	if (length <= 125) {
		frame[1]        = length & 0x7F;
		idx_first_rData = 2;

	} else if (length >= 126 && length <= 65535) {  /* Size between 126 and 65535 bytes. */
		frame[1]        = 126;
		frame[2]        = (length >> 8) & 255;
		frame[3]        = length & 255;
		idx_first_rData = 4;

	} else {  /* More than 65535 bytes. */
		frame[1]        = 127;
		frame[2]        = (unsigned char)((length >> 56) & 255);
		frame[3]        = (unsigned char)((length >> 48) & 255);
		frame[4]        = (unsigned char)((length >> 40) & 255);
		frame[5]        = (unsigned char)((length >> 32) & 255);
		frame[6]        = (unsigned char)((length >> 24) & 255);
		frame[7]        = (unsigned char)((length >> 16) & 255);
		frame[8]        = (unsigned char)((length >> 8) & 255);
		frame[9]        = (unsigned char)(length & 255);
		idx_first_rData = 10;
	}

	/* Add frame bytes. */
	idx_response = 0;
	response     = calloc(idx_first_rData + length + 1, 1);

	if (!response) {
		return (-1);
	}

	for (i = 0; i < idx_first_rData; i++) {
		response[i] = frame[i];
		idx_response++;
	}

	/* Add data bytes. */
	for (i = 0; i < length; i++) {
		response[idx_response] = msg[i];
		idx_response++;
	}

	response[idx_response] = '\0';
	output                 = SEND(fd, response, idx_response);

	safe_free(response);
	return ((int)output);
}

int ws_sendframe_txt(int fd, const char *msg) {
	return ws_sendframe(fd, msg, (uint64_t)strlen(msg), WS_FR_OP_TXT);
}

int ws_close_client(int fd) {
	unsigned char clse_code[2];
	int cc;
	int i;

	/*
	 * Instead of using do_close(), we use this to avoid using
	 * msg_ctrl buffer from wfd and avoid a race condition
	 * if this is invoked asynchronously.
	 */
	cc           = WS_CLSE_NORMAL;
	clse_code[0] = (cc >> 8);
	clse_code[1] = (cc & 0xFF);

	if (ws_sendframe(CLI_SOCK(fd), (const char *)clse_code, sizeof(char) * 2, WS_FR_OP_CLSE) < 0) {
		logd("An error has occurred while sending closing frame!\n");
		return (-1);
	}

	return (0);
}

int is_control_frame(int frame) {
	return (frame == WS_FR_OP_CLSE || frame == WS_FR_OP_PING || frame == WS_FR_OP_PONG);
}

int do_close(struct ws_frame_data *wfd, int close_code) {
	int cc; /* Close code.           */

	/* If custom close-code. */
	if (close_code != -1) {
		cc = close_code;
		goto custom_close;
	}

	/* If empty or have a close reason, just re-send. */
	if (wfd->frame_size == 0 || wfd->frame_size > 2)
		goto send;

	/* Parse close code and check if valid, if not, we issue an protocol error. */
	if (wfd->frame_size == 1)
		cc = wfd->msg_ctrl[0];
	else
		cc = ((int)wfd->msg_ctrl[0]) << 8 | wfd->msg_ctrl[1];

	/* Check if it's not valid, if so, we send a protocol error (1002). */
	if ((cc < 1000 || cc > 1003) && (cc < 1007 || cc > 1011) &&
		(cc < 3000 || cc > 4999))
	{
		cc = WS_CLSE_PROTERR;

	custom_close:
		wfd->msg_ctrl[0] = (cc >> 8);
		wfd->msg_ctrl[1] = (cc & 0xFF);

		if (ws_sendframe(CLI_SOCK(wfd->sock), (const char *)wfd->msg_ctrl, sizeof(char) * 2, WS_FR_OP_CLSE) < 0) {
			logd("An error has occurred while sending closing frame!\n");
			return (-1);
		}

		return (0);
	}

	/* Send the data inside wfd->msg_ctrl. */
send:
	if (ws_sendframe(CLI_SOCK(wfd->sock), (const char *)wfd->msg_ctrl, wfd->frame_size, WS_FR_OP_CLSE) < 0) {
		logd("An error has occurred while sending closing frame!\n");
		return (-1);
	}

	return (0);
}

int do_pong(struct ws_frame_data *wfd, uint64_t frame_size) {
	if (ws_sendframe(CLI_SOCK(wfd->sock), (const char *)wfd->msg_ctrl, frame_size, WS_FR_OP_PONG) < 0) {
		wfd->error = 1;
		logd("An error has occurred while ponging!\n");
		return (-1);
	}

	return (0);
}

int next_byte(struct ws_frame_data *wfd) {
	ssize_t n;

	/* If empty or full. */
	if (wfd->cur_pos == 0 || wfd->cur_pos == wfd->amt_read) {
		if ((n = RECV(wfd->sock, wfd->frm, sizeof(wfd->frm))) <= 0) {
			wfd->error = 1;
			logd("An error has occurred while trying to read next byte\n");
			return (-1);
		}

/*
		logd("Next bytes: [%d] \n"
			"------------------------------------\n"
			"%s\n"
			"------------------------------------\n",
			(int)n, wfd->frm);
*/

		wfd->amt_read = (size_t)n;
		wfd->cur_pos  = 0;
	}

//	logd("Next byte return: [%d] [%d]\n", (int)wfd->cur_pos + 1, wfd->frm[wfd->cur_pos + 1]);

	return (wfd->frm[wfd->cur_pos++]);
}

int skip_frame(struct ws_frame_data *wfd, uint64_t frame_size) {
	logd("%s [%d]\n", __FUNCTION__, __LINE__);

	uint64_t i;
	for (i = 0; i < frame_size; i++) {
		if (next_byte(wfd) == -1)
		{
			wfd->error = 1;
			return (-1);
		}
	}
	return (0);
}

int read_frame(struct ws_frame_data *wfd,
	int opcode,
	unsigned char **buf,
	uint64_t *frame_length,
	uint64_t *frame_size,
	uint64_t *msg_idx,
	uint8_t *masks,
	int is_fin)
{
	unsigned char *tmp; /* Tmp message.     */
	unsigned char *msg; /* Current message. */
	int cur_byte;       /* Curr byte read.  */
	uint64_t i;         /* Loop index.      */

	msg = *buf;

	/* Decode masks and length for 16-bit messages. */
	if (*frame_length == 126) {
		logd("Decode masks and length for 16-bit messages.\n");
		*frame_length = (((uint64_t)next_byte(wfd)) << 8) | next_byte(wfd);

	/* 64-bit messages. */
	} else if (*frame_length == 127) {
		logd("64-bit messages.\n");
		*frame_length =
			(((uint64_t)next_byte(wfd)) << 56) | /* frame[2]. */
			(((uint64_t)next_byte(wfd)) << 48) | /* frame[3]. */
			(((uint64_t)next_byte(wfd)) << 40) | (((uint64_t)next_byte(wfd)) << 32) |
			(((uint64_t)next_byte(wfd)) << 24) | (((uint64_t)next_byte(wfd)) << 16) |
			(((uint64_t)next_byte(wfd)) << 8) |
			(((uint64_t)next_byte(wfd))); /* frame[9]. */
	}

	*frame_size += *frame_length;

	/*
	 * Check frame size
	 *
	 * We need to limit the amount supported here, since if
	 * we follow strictly to the RFC, we have to allow 2^64
	 * bytes. Also keep in mind that this is still true
	 * for continuation frames.
	 */
	if (*frame_size > MAX_FRAME_LENGTH) {
		logd("Current frame from client %d, exceeds the maximum\n"
			  "amount of bytes allowed (%" PRId64 "/%d)!",
			wfd->sock, *frame_size + *frame_length, MAX_FRAME_LENGTH);

		wfd->error = 1;
		logd("%s [%d]\n", __FUNCTION__, __LINE__);
		return (-1);
	}

	/* Read masks. */
	if(wfd->masked) {
		masks[0] = next_byte(wfd);
		masks[1] = next_byte(wfd);
		masks[2] = next_byte(wfd);
		masks[3] = next_byte(wfd);
	}

	/*
	 * Abort if error.
	 *
	 * This is tricky: we may have multiples error codes from the
	 * previous next_bytes() calls, but, since we're only setting
	 * variables and flags, there is no major issue in setting
	 * them wrong _if_ we do not use their values, thing that
	 * we do here.
	 */
	if (wfd->error) {
		logd("%s [%d]\n", __FUNCTION__, __LINE__);
		return (-1);
	}

	/*
	 * Allocate memory.
	 *
	 * The statement below will allocate a new chunk of memory
	 * if msg is NULL with size total_length. Otherwise, it will
	 * resize the total memory accordingly with the message index
	 * and if the current frame is a FIN frame or not, if so,
	 * increment the size by 1 to accommodate the line ending \0.
	 */
	if (*frame_length > 0) {
		if (!is_control_frame(opcode)) {
			tmp = realloc(msg, sizeof(unsigned char) * (*msg_idx + *frame_length + is_fin));
			if (!tmp) {
				logd("Cannot allocate memory, requested: % " PRId64 "\n",
					(*msg_idx + *frame_length + is_fin));

				wfd->error = 1;
				logd("%s [%d]\n", __FUNCTION__, __LINE__);
				return (-1);
			}
			msg  = tmp;
			*buf = msg;
		}

		/* Copy to the proper location. */
		for (i = 0; i < *frame_length; i++, (*msg_idx)++) {
			/* We were able to read? .*/
			cur_byte = next_byte(wfd);
			if (cur_byte == -1) {
				logd("%s [%d]\n", __FUNCTION__, __LINE__);
				return (-1);
			}

			if(wfd->masked) {
				msg[*msg_idx] = cur_byte ^ masks[i % 4];
			} else {
				msg[*msg_idx] = cur_byte;
			}
		}
	}

	/* If we're inside a FIN frame, lets... */
	if (is_fin && *frame_size > 0) {
		/* Increase memory if our FIN frame is of length 0. */
		if (!*frame_length && !is_control_frame(opcode)) {
			tmp = realloc(msg, sizeof(unsigned char) * (*msg_idx + 1));
			if (!tmp) {
				logd("Cannot allocate memory, requested: %" PRId64 "\n",
					(*msg_idx + 1));

				wfd->error = 1;
				logd("%s [%d]\n", __FUNCTION__, __LINE__);
				return (-1);
			}

			msg  = tmp;
			*buf = msg;
		}

		msg[*msg_idx] = '\0';
	}

	return (0);
}

int next_frame(struct ws_frame_data *wfd) {
	unsigned char *msg_data; /* Data frame.                */
	unsigned char *msg_ctrl; /* Control frame.             */
	uint8_t masks_data[4];   /* Masks data frame array.    */
	uint8_t masks_ctrl[4];   /* Masks control frame array. */
	uint64_t msg_idx_data;   /* Current msg index.         */
	uint64_t msg_idx_ctrl;   /* Current msg index.         */
	uint64_t frame_length;   /* Frame length.              */
	uint64_t frame_size;     /* Current frame size.        */
	uint32_t utf8_state;     /* Current UTF-8 state.       */
	uint8_t opcode;          /* Frame opcode.              */
	uint8_t is_fin;          /* Is FIN frame flag.         */
	uint8_t mask;            /* Mask.                      */
	int cur_byte;            /* Current frame byte.        */

	msg_data        = NULL;
	msg_ctrl        = wfd->msg_ctrl;
	is_fin          = 0;
	frame_length    = 0;
	frame_size      = 0;
	msg_idx_data    = 0;
	msg_idx_ctrl    = 0;
	wfd->frame_size = 0;
	wfd->frame_type = -1;
	wfd->msg        = NULL;
	utf8_state      = UTF8_ACCEPT;

	/* Read until find a FIN or a unsupported frame. */
	do {
		/*
		 * Obs: next_byte() can return error if not possible to read the
		 * next frame byte, in this case, we return an error.
		 *
		 * However, please note that this check is only made here and in
		 * the subsequent next_bytes() calls this also may occur too.
		 * wsServer is assuming that the client only create right
		 * frames and we will do not have disconnections while reading
		 * the frame but just when waiting for a frame.
		 */
		cur_byte = next_byte(wfd);
		if (cur_byte == -1) {
			return (-1);
		}

		is_fin = (cur_byte & 0xFF) >> WS_FIN_SHIFT;
		opcode = (cur_byte & 0xF);

		/*
		 * Check for RSV field.
		 *
		 * Since wsServer do not negotiate extensions if we receive
		 * a RSV field, we must drop the connection.
		 */
		if (cur_byte & 0x70) {
			logd("RSV is set while wsServer do not negotiate extensions!\n");
			wfd->error = 1;
			break;
		}

		/*
		 * Check if the current opcode makes sense:
		 * a) If we're inside a cont frame but no previous data frame
		 *
		 * b) If we're handling a data-frame and receive another data
		 *    frame. (it's expected to receive only CONT or control
		 *    frames).
		 *
		 * It is worth to note that in a), we do not need to check
		 * if the previous frame was FIN or not: if was FIN, an
		 * on_message event was triggered and this function returned;
		 * so the only possibility here is a previous non-FIN data
		 * frame, ;-).
		 */
		if ((wfd->frame_type == -1 && opcode == WS_FR_OP_CONT) || \
		(wfd->frame_type != -1 && !is_control_frame(opcode) && opcode != WS_FR_OP_CONT)) {
			logd("Unexpected frame was received!, opcode: %d, previous: %d\n",
				opcode, wfd->frame_type);
			wfd->error = 1;
			break;
		}

		/* Check if one of the valid opcodes. */
		if (opcode == WS_FR_OP_TXT || opcode == WS_FR_OP_BIN ||
			opcode == WS_FR_OP_CONT || opcode == WS_FR_OP_PING ||
			opcode == WS_FR_OP_PONG || opcode == WS_FR_OP_CLSE) {
			/*
			 * Check our current state: if CLOSING, we only accept close
			 * frames.
			 *
			 * Since the server may, at any time, asynchronously, asks
			 * to close the client connection, we should terminate
			 * immediately.
			 */
			if (wfd->state == WS_STATE_CLOSING && opcode != WS_FR_OP_CLSE) {
				logd("Unexpected frame received, expected CLOSE (%d), received: (%d)",
					WS_FR_OP_CLSE, opcode);
				wfd->error = 1;
				break;
			}

			/* Only change frame type if not a CONT frame. */
			if (opcode != WS_FR_OP_CONT && !is_control_frame(opcode)) {
				wfd->frame_type = opcode;
			}

			mask         = next_byte(wfd);
			frame_length = mask & 0x7F;
			frame_size   = 0;
			msg_idx_ctrl = 0;
			wfd->masked  = mask >> 7;

			/*
			 * We should deny non-FIN control frames or that have
			 * more than 125 octets.
			 */
			if (is_control_frame(opcode) && (!is_fin || frame_length > 125)) {
				logd("Control frame bigger than 125 octets or not a FIN frame!\n");
				wfd->error = 1;
				break;
			}

			/* Normal data frames. */
			if (opcode == WS_FR_OP_TXT || opcode == WS_FR_OP_BIN ||
				opcode == WS_FR_OP_CONT) {
				read_frame(wfd, opcode, &msg_data, &frame_length, &wfd->frame_size,
					&msg_idx_data, masks_data, is_fin);

#ifdef VALIDATE_UTF8
				/* UTF-8 Validate partial (or not) frame. */
				if (wfd->frame_type == WS_FR_OP_TXT) {
					if (is_fin) {
						if (is_utf8_len_state(
								msg_data + (msg_idx_data - frame_length),
								frame_length, utf8_state) != UTF8_ACCEPT) {
							logd("Dropping invalid complete message!\n");
							wfd->error = 1;
							do_close(wfd, WS_CLSE_INVUTF8);
						}

					} else { /* Check current state for a CONT or initial TXT frame. */
						utf8_state = is_utf8_len_state(
							msg_data + (msg_idx_data - frame_length), frame_length,
							utf8_state);

						/* We can be in any state, except reject. */
						if (utf8_state == UTF8_REJECT) {
							logd("Dropping invalid cont/initial frame!\n");
							wfd->error = 1;
							do_close(wfd, WS_CLSE_INVUTF8);
						}
					}
				}
#endif
			}

			/*
			 * We _never_ send a PING frame, so it's not expected to receive a PONG
			 * frame. However, the specs states that a client could send an
			 * unsolicited PONG frame. The server just have to ignore the
			 * frame.
			 *
			 * The skip amount will always be 4 (masks vector size) + frame size
			 */
			else if (opcode == WS_FR_OP_PONG) {

				logd("%s [%d]\n", __FUNCTION__, __LINE__);
				skip_frame(wfd, 4 + frame_length);
				is_fin = 0;
				continue;
			}

			/* We should answer to a PING frame as soon as possible. */
			else if (opcode == WS_FR_OP_PING) {

				logd("%s [%d]\n", __FUNCTION__, __LINE__);
				if (read_frame(wfd, opcode, &msg_ctrl, &frame_length, &frame_size,
						&msg_idx_ctrl, masks_ctrl, is_fin) < 0) {
					break;
				}

				if (do_pong(wfd, frame_size) < 0) {
					break;
				}

				/* Quick hack to keep our loop. */
				is_fin = 0;

			} else {  /* We interrupt the loop as soon as we find a CLOSE frame. */
				if (read_frame(wfd, opcode, &msg_ctrl, &frame_length, &frame_size,
						&msg_idx_ctrl, masks_ctrl, is_fin) < 0)
					break;

#ifdef VALIDATE_UTF8
				/* If there is a close reason, check if it is UTF-8 valid. */
				if (frame_size > 2 && !is_utf8_len(msg_ctrl + 2, frame_size - 2)) {
					logd("Invalid close frame payload reason! (not UTF-8)\n");
					wfd->error = 1;
					break;
				}
#endif

				/* Since we're aborting, we can scratch the 'data'-related
				 * vars here. */
				wfd->frame_size = frame_size;
				wfd->frame_type = WS_FR_OP_CLSE;
				free(msg_data);
				return (0);
			}

		} else {  /* Anything else (unsupported frames). */
			logd("Unsupported frame opcode: %d\n", opcode);
			/* We should consider as error receive an unknown frame. */
			wfd->frame_type = opcode;
			wfd->error      = 1;
		}

	} while (!is_fin && !wfd->error);

	/* Check for error. */
	if (wfd->error) {
		free(msg_data);
		wfd->msg = NULL;
		logd("Error");
		return (-1);
	}

	wfd->msg = msg_data;
	return (0);
}

ws_frame_data_t *ws_establishconnection(int socket) {
	ws_frame_data_t *wfd = calloc(sizeof(*wfd), 1); /* WebSocket frame data.   */

	struct sockaddr_in sa;
	int sl = sizeof(struct sockaddr_in);

	if (getpeername(socket, (struct sockaddr *)&sa, &sl)) {
		logd("Error on getpeername..");
		abort();
	}

	sprintf(wfd->ip, "%s", inet_ntoa(sa.sin_addr));
	wfd->sock = socket;
	wfd->port = ntohs(sa.sin_port);
	wfd->state = WS_STATE_CONNECTING;

	return wfd;
}

bool do_handshake(struct ws_frame_data *wfd) {
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
	wfd->ip, wfd->port);

	int output = SEND(wfd->sock, buf, strlen(buf));

	if (output <= 0) {
		logd("Failed to do_handshake");
		return false;
	}

	return true;
}

bool return_handshake(struct ws_frame_data *wfd) {
	char *response; /* Handshake response message. */
	char *p;        /* Last request line pointer.  */
	ssize_t n;      /* Read/Write bytes.           */

	/* Read the very first client message. */
	if ((n = RECV(wfd->sock, wfd->frm, sizeof(wfd->frm) - 1)) < 0) {
		wfd->state = WS_STATE_CLOSED;
		return false;
	}

	logd("------------------------------------\n"
	     "%s\n"
	     "------------------------------------\n",
	(char *)wfd->frm);

	/* Advance our pointers before the first next_byte(). */
	p = strstr((const char *)wfd->frm, "\r\n\r\n");
	if (p == NULL) {
		logd("An empty line with \\r\\n was expected!\n");
		wfd->state = WS_STATE_CLOSED;
		return false;
	}

	wfd->amt_read = n;
	wfd->cur_pos  = (size_t)((ptrdiff_t)(p - (char *)wfd->frm)) + 4;

	/* Get response. */
	if (get_handshake_response((char *)wfd->frm, &response) < 0) {
		logd("Cannot get handshake response, request was: %s\n", wfd->frm);
		wfd->state = WS_STATE_CLOSED;
		return false;
	}

	/* Valid request. */
	logd("Handshaked, response: \n"
		"------------------------------------\n"
		"%s\n"
		"------------------------------------\n",
		response);

	/* Send handshake. */
	if (SEND(wfd->sock, response, strlen(response)) <= 0) {
		free(response);
		logd("As error has occurred while handshaking!\n");
		wfd->state = WS_STATE_CLOSED;
		return false;
	}

	/* Change state. */
	wfd->state = WS_STATE_OPEN;

	/* Trigger events and clean up buffers. */
	free(response);
	return true;
}

bool finish_handshake(ws_frame_data_t *wfd) {
	char *p;        /* Last request line pointer.  */
	ssize_t n;      /* Read/Write bytes.           */

	/* Read the very first client message. */
	if ((n = RECV(wfd->sock, wfd->frm, sizeof(wfd->frm) - 1)) < 0) {
		return false;
	}

	logd("Got handshake: \n"
		"------------------------------------\n"
		"%s"
		"------------------------------------\n",
		(char *)wfd->frm);

	/* Advance our pointers before the first next_byte(). */
	p = strstr((const char *)wfd->frm, "\r\n\r\n");
	if (p == NULL) {
		logd("An empty line with \\r\\n was expected!\n");
		return false;
	}

	wfd->amt_read = n;
	wfd->cur_pos  = (size_t)((ptrdiff_t)(p - (char *)wfd->frm)) + 4;
	wfd->state = WS_STATE_OPEN;

	return true;
}


