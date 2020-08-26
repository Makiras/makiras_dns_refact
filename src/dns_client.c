/*
 * @Author: Makiras
 * @Date: 2020-08-06 11:26:35
 * @LastEditTime: 2020-08-06 20:19:19
 * @LastEditors: Makiras
 * @Description: 
 * @FilePath: \makiras_dns_refact\dns_client.c
 * @Licensed under the Apache License, Version 2.0 (the "License");
 * @Copyright 2020 @Makiras
 */

#include "dns_client.h"
struct sockaddr_in addr;
char *buffer_rec, flag;
int sent_pack_id = 0;
char packet_raw_buffer[DNS_MAX_PACK_SIZE];
uv_udp_send_t req;
uv_buf_t buf;

//todo: cache
DnsRR *check_cache(int qtype, const char *domain_name)
{
    return NULL;
}

static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    static char slab[DNS_MAX_PACK_SIZE];
    buffer_rec = slab;
    buf->base = slab;
    buf->len = sizeof(slab);
    return;
}

static void close_cb(uv_handle_t *handle)
{
    // uv_is_closing(handle);
    return;
}

static void cl_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *rcvbuf, const struct sockaddr *addr, unsigned flags)
{
    uv_udp_send_t *req;
    uv_buf_t sndbuf;
    char ipaddr[17] = {0};
    uv_ip4_name(&addr, ipaddr, sizeof(ipaddr));
    if (nread <= 0)
    {
        printf("[ERROR] Detected %s trans error or null trans, len :%d !\n", ipaddr, nread);
        return;
    }
    uv_close((uv_handle_t *)handle, close_cb);
    printf("[INFO] receive relay message from: %s, length: %d\n", ipaddr, nread);
    print_dns_raw(rcvbuf->base, nread);
    fflush(stdout);
    memcpy(packet_raw_buffer, rcvbuf->base, nread);
    flag = 1;
    return;
}

static void cl_send_cb(uv_udp_send_t *req, int status)
{
    puts("[INFO] Start Client Send callback");
    uv_udp_recv_start(req->handle, alloc_cb, cl_recv_cb);
    return;
}

int dns_client_init()
{
    // send & listen
    printf("[Info] Start init client.\n");
    uv_ip4_addr("0.0.0.0", 0, &addr);
    uv_udp_init(loop, &send_socket);
    uv_udp_bind(&send_socket, (const struct sockaddr *)&addr, UV_UDP_REUSEADDR);
    uv_udp_set_broadcast(&send_socket, 1);
    return 0;
}

DnsPacket *query_packet_init()
{
    DnsPacket *req_pack = (DnsPacket *)malloc(sizeof(DnsPacket));
    req_pack->header.id = ++sent_pack_id;
    req_pack->header.qr = DNS_QR_QUERY;
    req_pack->header.opcode = DNS_OPC_QUERY;
    req_pack->header.tc = 1;
    req_pack->header.rd = 1;
    req_pack->header.ra = 1;
    req_pack->header.rcode = 0;
    req_pack->header.qdcount = 1;
    req_pack->header.ancount = 0;
    req_pack->header.nscount = 0;
    req_pack->header.arcount = 0;
    return req_pack;
}

DnsRR *query_RR_init(const char *qname, cshort qtype, cshort qclass)
{
    DnsRR *qd_RR = (DnsRR *)malloc(sizeof(DnsRR));
    qd_RR->name = (char *)malloc(strlen(qname) + 1);
    strncpy(qd_RR->name, qname, strlen(qname));
    puts(qd_RR->name);
    qd_RR->type = qtype;
    qd_RR->cls = qclass;
    qd_RR->next = NULL;
    return qd_RR;
}

DnsRR *query_A_res(const char *domain_name)
{
    if (check_cache(DNS_RRT_A, domain_name) != NULL)
    {
        //todo: do cache
    }
    else
    {
        flag = 0;
        char *bias;
        DnsPacket *qd_packet = query_packet_init();
        qd_packet->records = query_RR_init(domain_name, DNS_RRT_A, DNS_RCLS_IN);
        printf("[Info] cache miss for %s, send for more infomation\n", domain_name);
        print_dns_packet(qd_packet);
        bias = _dns_encode_packet(packet_raw_buffer, qd_packet);
        print_dns_raw(packet_raw_buffer, bias - packet_raw_buffer);
        buf = uv_buf_init(packet_raw_buffer, bias - packet_raw_buffer);
        uv_ip4_addr("223.5.5.5", 53, &addr);
        int r = uv_udp_send(&req, &send_socket, &buf, bias - packet_raw_buffer, &addr, cl_send_cb);
        printf("Error %s\n", uv_strerror(r));
    }
    return NULL;
}