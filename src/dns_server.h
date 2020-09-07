#ifndef _DNS_SERVER_H
#define _DNS_SERVER_H
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include "dns_client.h"

extern uv_loop_t *loop;
extern int BIND_IPV6;
extern int ENABLE_EXP;
extern char *BIND_ADDR;

int dns_server_init();


#endif