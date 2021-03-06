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

extern uv_loop_t *client_loop;

extern int ENABLE_DNSOPT;
extern char *DOT_SERVER;
extern char *DNS_SERVER;
extern int ENABLE_DOT;
extern int ENABLE_EXP;

typedef struct DnsQRes{
    DnsRR* rr;
    int rcode;
} DnsQRes;

int dns_client_init();
void dns_cache_init();
DnsQRes* query_exp_res(const int type, const char *domain_name);
DnsQRes* query_A_res(const char* domain_name);
DnsQRes* query_AAAA_res(const char* domain_name);
DnsQRes* query_CNAME_res(const char* domain_name);

#endif