/*
  hpfeeds.h
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

#ifndef __hpfeeds_h
#define __hpfeeds_h

#include <sys/types.h>
#include <stdint.h>

#define	OP_ERROR 0
#define	OP_INFO	1
#define	OP_AUTH	2
#define	OP_PUBLISH 3
#define	OP_SUBSCRIBE 4

typedef enum {
S_INIT,
S_ERROR,
S_CONNECTED,
S_AUTH,
S_SUBSCRIBE,
S_PUBLISH,
S_RECVMSGS,
S_TERMINATE
} session_state_t;


#pragma pack(1)
typedef struct {
		uint32_t msglen;
		uint8_t opcode;
} hpf_hdr_t;

typedef struct {
    hpf_hdr_t hdr;	
	uint8_t data[];
} hpf_msg_t;

#pragma pack()

typedef struct {
	u_char len;
	u_char data[];
} hpf_chunk_t;

typedef struct {
    int sock_fd;
    char* host;
    char* service;
    //struct addrinfo addr;
    int sent_bytes;
    int received_bytes;
    int status;
} hpf_handle_t;

//typedef struct hpf_chann {
//    char* chan_name;
//    int sent_bytes;
//    int sent_msg;
//    bool publish;
//    int recv_bytes;
//    int recv_msg;
//    struct hpf_chann* next;
//} hpf_chann_t;



hpf_msg_t *hpf_msg_getmsg(uint8_t *data);
u_int32_t hpf_msg_getsize(hpf_msg_t *m);
u_int32_t hpf_msg_gettype(hpf_msg_t *m);

hpf_chunk_t *hpf_msg_get_chunk(uint8_t *data, size_t len);

/* all this function used to create/ delete messages */
hpf_msg_t *hpf_msg_create(void);
hpf_msg_t *hpf_msg_error_create(uint8_t *err, size_t err_size);
hpf_msg_t *hpf_msg_info_create(uint32_t nonce, uint8_t *fbname, size_t fbname_len);
hpf_msg_t *hpf_msg_auth_create(uint32_t nonce, uint8_t *ident, size_t ident_len, uint8_t *secret, size_t secret_len);
hpf_msg_t *hpf_msg_publish_create(uint8_t *ident, size_t ident_len, uint8_t *channel, size_t channel_len, uint8_t *data, size_t data_len);
hpf_msg_t *hpf_msg_subscribe_create(uint8_t *ident, size_t ident_len, uint8_t *channel, size_t channel_len);
void hpf_msg_delete(hpf_msg_t *m);


/* high level funtion used by clients... */

int hpf_connect(hpf_handle_t** handle, char* host, char* service);
int hpf_authenticate(hpf_handle_t* handle, char* ident, char* secret);
int hpf_msg_write(hpf_handle_t* handle, hpf_msg_t* msg);
uint8_t hpf_msg_read(hpf_handle_t* handle);
void hpf_close(hpf_handle_t* handle);
void hpf_free(hpf_handle_t* handle);



#endif
