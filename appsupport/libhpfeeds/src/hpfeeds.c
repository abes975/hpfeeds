/*
  hpfeeds.c
  Copyright (C) 2011 The Honeynet Project
  Copyright (C) 2011 Tillmann Werner, tillmann.werner@gmx.de

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License version 2 as 
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <hpfeeds.h>

#include "sha1.h"

static u_char* read_data(hpf_handle_t* handle);

hpf_msg_t *hpf_msg_create(void) {
	hpf_msg_t *msg;

	msg = calloc(1, sizeof(hpf_msg_t));
	msg->hdr.msglen = htonl(sizeof(msg->hdr));

	return msg;
}

void hpf_msg_delete(hpf_msg_t *m) {
	if (m) free(m);
    return;
}

hpf_msg_t *hpf_msg_getmsg(u_char *data) {
	return (hpf_msg_t *) data;
}

u_int32_t hpf_msg_getsize(hpf_msg_t *m) {
	return ntohl(m->hdr.msglen);
}

u_int32_t hpf_msg_gettype(hpf_msg_t *m) {
	return m->hdr.opcode;
}

uint8_t* read_data(hpf_handle_t* handle)
{
    uint8_t* buffer;
    hpf_hdr_t hdr;
    int hdrlen = sizeof(hpf_hdr_t);
	int len = 0;
	int dummylen = 0;

    if (!handle) {
        fprintf(stderr, "Cannot read data from a NULL handle\n");
        exit(EXIT_FAILURE);
    }
    
    if (handle->sock_fd == -1) {
        fprintf(stderr, "Cannot read data %d socket descriptor\n", 
            handle->sock_fd);
        exit(EXIT_FAILURE);
    }
    
   	if (read(handle->sock_fd, &hdr, hdrlen) != hdrlen) {
		fprintf(stderr, "read(), not enough data to get msg header\n");
		exit(EXIT_FAILURE);
	}

    hdr.msglen = ntohl(hdr.msglen);

    buffer = (uint8_t*)malloc(hdr.msglen * sizeof(uint8_t));
	if (!buffer) {
		fprintf(stderr, "Cannot allocate buffer to copy message."
            " Needed (%d) bytes\n", hdr.msglen);
		exit(EXIT_FAILURE);
	}

    /* copy header bytes..used to allocate memory buffer */
    memcpy(buffer, &hdr, hdrlen);
    len += hdrlen;
    while (len < hdr.msglen) {
        if ((dummylen = read(handle->sock_fd, &buffer[len], hdr.msglen) != -1))
            len += dummylen;
        else {
            fprintf(stderr, "Error (%s) while reading from %d socket\n", 
                strerror(errno), handle->sock_fd);
            free(buffer);
            exit(EXIT_FAILURE);
        }
    }

	if (len != hdr.msglen) {
		fprintf(stderr, "Got %d but should have gotten %d...error detected\n",
            len, hdr.msglen);
        free(buffer);
		exit(EXIT_FAILURE);
	}

	return buffer;
}

hpf_msg_t *hpf_msg_add_chunk(hpf_msg_t **m, const u_char *data, size_t len) {
	hpf_msg_t *msg = *m;
	u_char l;

	if (!m || !data || !len)
		return NULL;

	l = len < 0xff ? len : 0xff;

	*m = msg = realloc(msg, ntohl(msg->hdr.msglen) + l + 1);

	if (msg == NULL)
		return NULL;

	((u_char *) msg)[ntohl(msg->hdr.msglen)] = l;
	memcpy(((u_char *) msg) + ntohl(msg->hdr.msglen) + 1, data, l);

	msg->hdr.msglen = htonl(ntohl(msg->hdr.msglen) + 1 + l);

	return msg;
}

hpf_chunk_t *hpf_msg_get_chunk(u_char *data, size_t len) {
	hpf_chunk_t *c;

	if (!data || !len) return NULL;

	c = (hpf_chunk_t *) data;

	// incomplete chunk?
	if (c->len > len + 1) return NULL;

	return c;
}

hpf_msg_t *hpf_msg_add_payload(hpf_msg_t **m, const u_char *data, size_t len) {
	hpf_msg_t *msg = *m;

	if (!m || !data || !len)
		return NULL;

	*m = msg = realloc(msg, ntohl(msg->hdr.msglen) + len);

	if (msg == NULL)
		return NULL;

	memcpy(((u_char *) msg) + ntohl(msg->hdr.msglen), data, len);

	msg->hdr.msglen = htonl(ntohl(msg->hdr.msglen) + len);

	return msg;
}

hpf_msg_t *hpf_msg_error_create(u_char *err, size_t err_size) {
	hpf_msg_t *msg;

	msg = hpf_msg_create();

	if (msg == NULL)
		return NULL;

	msg->hdr.opcode = OP_ERROR;

	hpf_msg_add_payload(&msg, err, err_size);

	return msg;
}

hpf_msg_t *hpf_msg_info_create(u_int32_t nonce, u_char *fbname, size_t fbname_len) {
	hpf_msg_t *msg;

	msg = hpf_msg_create();

	if (msg == NULL)
		return NULL;

	msg->hdr.opcode = OP_INFO;

	hpf_msg_add_chunk(&msg, fbname, fbname_len);

	hpf_msg_add_payload(&msg, (u_char *) &nonce, sizeof(u_int32_t));

	return msg;
}

hpf_msg_t *hpf_msg_auth_create(u_int32_t nonce, u_char *ident, size_t ident_len, u_char *secret, size_t secret_len) {
	hpf_msg_t *msg;
	SHA1Context ctx;
	u_char hash[SHA1HashSize];

	msg = hpf_msg_create();

	if (msg == NULL)
		return NULL;	

	msg->hdr.opcode = OP_AUTH;

	SHA1Reset(&ctx);
	SHA1Input(&ctx, (u_int8_t *) &nonce, sizeof(nonce));
	SHA1Input(&ctx, (u_int8_t *) secret, secret_len);
	SHA1Result(&ctx, hash);

	hpf_msg_add_chunk(&msg, ident, ident_len);

	hpf_msg_add_payload(&msg, hash, SHA1HashSize);

	return msg;
}

hpf_msg_t *hpf_msg_publish_create(u_char *ident, size_t ident_len, u_char *channel, size_t channel_len, u_char *data, size_t data_len) {
	hpf_msg_t *msg;

	msg = hpf_msg_create();

	if (msg == NULL)
		return NULL;

	msg->hdr.opcode = OP_PUBLISH;

	hpf_msg_add_chunk(&msg, ident, ident_len);
	hpf_msg_add_chunk(&msg, channel, channel_len);

	hpf_msg_add_payload(&msg, data, data_len);

	return msg;
}

hpf_msg_t *hpf_msg_subscribe_create(u_char *ident, size_t ident_len, u_char *channel, size_t channel_len) {
	hpf_msg_t *msg;

	msg = hpf_msg_create();

	if (msg == NULL)
		return NULL;

	msg->hdr.opcode = OP_SUBSCRIBE;

	hpf_msg_add_chunk(&msg, ident, ident_len);

	hpf_msg_add_payload(&msg, channel, channel_len);

	return msg;
}

int hpf_connect(hpf_handle_t** handle, char* host, char* service)
{
    struct addrinfo* res;
    struct addrinfo* rptr;
    struct addrinfo hints;
    int err;
    
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICSERV;

    
    if((err = getaddrinfo(host, service, NULL, &res))) {
        gai_strerror(err);
        exit(EXIT_FAILURE);
    }

    // We call the same function if the socket has closed 
    if (!*handle) {
        *handle = (hpf_handle_t*)calloc(1, sizeof(hpf_handle_t));
        if (!*handle) {
            fprintf(stderr, "Can't allocate connection handle\n");
            exit(EXIT_FAILURE);
        }
    }

    /* let's connect until success or getaddrinfo result finishes */
    for (rptr = res; rptr != NULL; rptr = rptr->ai_next) {
        (*handle)->sock_fd = socket(rptr->ai_family, rptr->ai_socktype, 
            rptr->ai_protocol);
        if ((*handle)->sock_fd == -1) {
            fprintf(stderr, "Creation of socket failed for family %d, "
                "socktype %d protocol %d\n", rptr->ai_family, rptr->ai_socktype, 
                rptr->ai_protocol);
            continue;
        }
        
        if(connect((*handle)->sock_fd, rptr->ai_addr, rptr->ai_addrlen) == -1) {
            fprintf(stderr, "Can't connect to socket\n");
            (*handle)->sock_fd = -1;
            continue;
        }
        // let's copy host and port....and struct we used to connect...
        (*handle)->host = (char*) malloc(sizeof(strlen(host) * sizeof(char)));
        if (!(*handle)->host) {
            fprintf(stderr, "Can't allocate host string\n");
            exit(EXIT_FAILURE);
        }
        strncpy((*handle)->host, host, strlen(host));
        (*handle)->service = (char*) malloc(sizeof(strlen(service) * sizeof(char)));
        if (!(*handle)->service) {
            fprintf(stderr, "Can't allocate service string\n");
            exit(EXIT_FAILURE);
        }
        strncpy((*handle)->service, service, strlen(service));
        break;
    }
    
    freeaddrinfo(res);
    // Did we succeeded?
    if ((*handle)->sock_fd == -1) {
        free(*handle);
        fprintf(stderr, "Can't connect to hpfeed broker...giving up\n");
        exit(EXIT_FAILURE);
    }

    (*handle)->status = S_CONNECTED;
    return EXIT_SUCCESS;
}
 
void hpf_close(hpf_handle_t* handle)
{
    if (!handle) {
        fprintf(stderr, "Can't disconnect, handle is invalid...giving up\n");
        exit(EXIT_FAILURE);
    }
    if (handle->sock_fd != -1) 
        close(handle->sock_fd);
    
    handle->status = S_TERMINATE;
}

void hpf_free(hpf_handle_t* handle)
{
    if (!handle) {
        fprintf(stderr, "Can't disconnect, handle is invalid...giving up\n");
        exit(EXIT_FAILURE);
    }

    if(handle->status != S_TERMINATE)
        hpf_close(handle);

    free(handle->host);
    free(handle->service);
    free(handle);
    handle = NULL;
}

int hpf_authenticate(hpf_handle_t* handle, char* ident, char* secret)
{
    u_char* data;
    uint32_t nonce = 0;
    hpf_hdr_t* hdr;
    hpf_msg_t *msg;

    if (handle->status == S_AUTH) {
        fprintf(stderr, "Already authenticated\n");
        return 1;
    }

    if (handle->status != S_CONNECTED) {
        fprintf(stderr, "Cannot authenticated... handle status is %d\n",
            handle->status);
        return 0;
    }

    data = read_data(handle);
    /* get op code */
    hdr = (hpf_hdr_t*)data;
    //data += hdr->msglen;

    switch(hdr->opcode) {
        hpf_chunk_t* chunk = NULL;
        case OP_INFO:
            chunk = (hpf_chunk_t*)(data + hdr->msglen);

            if (chunk->len != sizeof(nonce)) {
                fprintf(stderr, "Invalid message format expected %d bytes, " 
                    "got %d\n", chunk->len, sizeof(nonce));
                exit(EXIT_FAILURE);
            }
            /* we have a copy of nonce */
            char* dummy = (char*) (chunk->data);
			nonce = *(uint32_t *) dummy;

            free(data);

            // send auth message
		    fprintf(stderr, "Sending authentication...for nonce %d\n", nonce);
    		msg = hpf_msg_auth_create(nonce, (uint8_t*) ident, strlen(ident), (uint8_t*) secret, strlen(secret));

		    if (write(handle->sock_fd, (uint8_t*) msg, ntohl(msg->hdr.msglen)) == -1) {
			    perror("write()");
			    exit(EXIT_FAILURE);
		    }
		    hpf_msg_delete(msg);

			handle->status = S_AUTH;

			break;
		case OP_ERROR:
			handle->status  = S_ERROR;
		    fprintf(stderr, "Received OP_ERROR message\n");
			break;
		default:
			fprintf(stderr, "Unknown server message (type %u)\n", hdr->opcode);
			exit(EXIT_FAILURE);
		}
    return 1;
}


int hpf_message_write(hpf_handle_t* handle)
{
    if (!handle) {
        fprintf(stderr, "Cannot do a wirte on a NULL handle\n");
        exit(EXIT_FAILURE);
    }
    if (handle->sock_fd == -1 || handle->status == S_ERROR || handle->status == S_TERMINATE) {
        fprintf(stderr, "Cannot do a write on a closed section try to reconnect\n");
        hpf_connect(&handle, handle->host, handle->service);
    }
    // We expect write failures to occur but we want to handle them where 
    // the error occurs rather than in a SIGPIPE handler.
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

