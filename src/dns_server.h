#ifndef _DNS_SERVER_H
#define _DNS_SERVER_H
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include "dns_client.h"

extern uv_loop_t *loop;
static uv_udp_t recv_socket;
extern char* bind_address;

int dns_server_init();


#endif