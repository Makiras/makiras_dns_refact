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
struct sockaddr_in addr, send_addr;
static uv_buf_t client_buf;
static uv_udp_send_t client_req;
char *buffer_rec;
int sent_pack_id = 0, flag = 0;
char packet_raw_buffer[DNS_MAX_PACK_SIZE], packet_res_buffer[DNS_MAX_PACK_SIZE];

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
    uv_is_closing(handle);
    return;
}

static void cl_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *rcvbuf, const struct sockaddr *addr, unsigned flags)
{
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
    memcpy(packet_res_buffer, rcvbuf->base, nread);
    flag = nread;
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
    uv_udp_init(client_loop, &send_socket);
    uv_udp_bind(&send_socket, (const struct sockaddr *)&addr, UV_UDP_REUSEADDR);
    uv_udp_set_broadcast(&send_socket, 1);
    flag = 0;
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
    qd_RR->name[strlen(qname)] = '\0';
    puts(qd_RR->name);
    qd_RR->type = qtype;
    qd_RR->cls = qclass;
    qd_RR->next = NULL;
    return qd_RR;
}

DnsQRes *query_res(const int type, const char *domain_name)
{
    // Init packet data
    DnsPacket *qd_packet = query_packet_init();
    switch (type)
    {
    case DNS_RRT_A:
        qd_packet->records = query_RR_init(domain_name, DNS_RRT_A, DNS_RCLS_IN);
        break;
    case DNS_RRT_AAAA:
        qd_packet->records = query_RR_init(domain_name, DNS_RRT_AAAA, DNS_RCLS_IN);
        break;
    case DNS_RRT_CNAME:
        qd_packet->records = query_RR_init(domain_name, DNS_RRT_CNAME, DNS_RCLS_IN);
        break;
    default:
        return NULL;
        break;
    }
    print_dns_packet(qd_packet);
    char *bias = _dns_encode_packet(packet_raw_buffer, qd_packet);

    // Debug infomation
    printf("[Info] cache miss for %s, send for more infomation\n", domain_name);
    print_dns_raw(packet_raw_buffer, bias - packet_raw_buffer);

    // Prepare sending data
    int data_len = bias - packet_raw_buffer;
    client_buf = uv_buf_init(packet_raw_buffer, data_len);

    // Sending & Waiting (multi-thread)
    dns_client_init();
    uv_ip4_addr("223.5.5.5", 53, &send_addr);
    int r = uv_udp_send(&client_req, &send_socket, &client_buf, 1, &send_addr, cl_send_cb);
    uv_run(client_loop, UV_RUN_DEFAULT);
    while (!flag) // wait for query finish
        ;
    printf("uv_udp_send %s\n", r ? "NOERR" : uv_strerror(r));

    // Handle Results
    char *raw_pack = (char *)malloc(flag * sizeof(char));
    DnsPacket *req_packet = (DnsPacket *)malloc(sizeof(DnsPacket));
    memcpy(raw_pack, packet_res_buffer, flag);
    _dns_decode_packet(raw_pack, req_packet); // has free raw_pack
    print_dns_packet(req_packet);

    // Get RR_Res & free mem
    DnsRR *now_rr = req_packet->records, *tempRR;
    DnsQRes *reslut = malloc(sizeof(DnsQRes));
    for (int i = 0; i < req_packet->header.qdcount; i++)
    {
        tempRR = now_rr->next;
        free(now_rr);
        now_rr = tempRR;
    }
    reslut->rr = now_rr;
    reslut->rcode = req_packet->header.rcode;
    free(req_packet);

    return reslut;
}

DnsQRes *query_A_res(const char *domain_name)
{
    if (check_cache(DNS_RRT_A, domain_name) != NULL)
    {
        //todo: do cache
    }
    else
        return query_res(DNS_RRT_A, domain_name);
}

DnsQRes *query_AAAA_res(const char *domain_name)
{
    if (check_cache(DNS_RRT_AAAA, domain_name) != NULL)
    {
        //todo: do cache
    }
    else
        return query_res(DNS_RRT_AAAA, domain_name);
}

DnsQRes *query_CNAME_res(const char *domain_name)
{
    if (check_cache(DNS_RRT_CNAME, domain_name) != NULL)
    {
        //todo: do cache
    }
    else
        return query_res(DNS_RRT_CNAME, domain_name);
}