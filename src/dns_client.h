/*
 * @Author: Makiras
 * @Date: 2020-08-06 11:26:31
 * @LastEditTime: 2020-08-06 21:01:47
 * @LastEditors: Makiras
 * @Description: 
 * @FilePath: \makiras_dns_refact\src\dns_client.h
 * @Licensed under the Apache License, Version 2.0 (the "License");
 * @Copyright 2020 @Makiras
 */

#ifndef _DNS_CLIENT_H
#define _DNS_CLIENT_H
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include "uni_dns.h"
#include "udefine.h"

extern uv_udp_t send_socket;
extern uv_loop_t *loop;

int dns_client_init();

DnsRR* query_A_res(const char* domain_name);

#endif