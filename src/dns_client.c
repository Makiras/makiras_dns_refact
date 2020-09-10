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
#include "rbtree.h"
#include <curl/curl.h>
#include <stdio.h>
#include <time.h>

struct sockaddr_in addr, send_addr;
static uv_udp_t send_socket;
static uv_buf_t client_buf;
static uv_udp_send_t client_req;

rbtree *cacheTree;
char *buffer_rec;
const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int sent_pack_id = 0, flag = 0, keep_lock = 0;
char packet_raw_buffer[DNS_MAX_PACK_SIZE], packet_res_buffer[DNS_MAX_PACK_SIZE];

void dns_cache_init()
{
    PLOG(LINFO, "[Cache]\tStart Dns Cache Init\n");

    cacheTree = rbtree_init(rb_compare);
    // Handle Host File
    FILE *fp = fopen("relay.txt", "r");
    if (fp == NULL)
        return;
    char cbuff[DNS_NSD_LEN_CNAME], cipbuff[DNS_NSD_LEN_CNAME / 2];
    while (fscanf(fp, "%s", cbuff) != EOF)
    {
        fscanf(fp, "%s", cipbuff);
        if (cbuff[strlen(cbuff) - 1] != '.')
        {
            cbuff[strlen(cbuff) + 1] = '\0';
            cbuff[strlen(cbuff)] = '.';
        }
        PLOG(LDEBUG, "[Cache]\tRead host for %s,%s\n", cbuff, cipbuff);
        if (strrchr(cipbuff, ':') == NULL) // ipv4
        {

            DnsRR *cache_res = rbtree_lookup(cacheTree, &(KEY){cbuff, DNS_RRT_A}),
                  *tba = malloc(sizeof(DnsRR));

            // Construct DnsRR package
            tba->name = malloc(strlen(cbuff) + 1);
            memcpy(tba->name, cbuff, strlen(cbuff) + 1);
            tba->type = DNS_RRT_A;
            tba->cls = DNS_RCLS_IN;
            tba->ttl = -1; // unsigned to max
            tba->rdlength = 4;
            tba->rdata = malloc(4);
            tba->next = NULL;
            memset(tba->rdata, 0, 4);
            for (int ipi = 0, rdi = 0; ipi < strlen(cipbuff); ipi++) // cover str to ipv4 addr
            {
                if (cipbuff[ipi] == '.' && ++rdi)
                    continue;
                tba->rdata[rdi] = tba->rdata[rdi] * 10 + cipbuff[ipi] - '0';
            }

            // add into resolve
            if (cache_res != NULL)
            {
                while (cache_res->next != NULL)
                    cache_res = cache_res->next;
                cache_res->next = tba;
            }
            else // new reslove
                rbtree_insert(cacheTree, &(KEY){cbuff, DNS_RRT_A}, tba);
        }
        else // ipv6
        {
            DnsRR *cache_res = rbtree_lookup(cacheTree, &(KEY){cbuff, DNS_RRT_AAAA}),
                  *tba = malloc(sizeof(DnsRR));

            // Construct DnsRR package
            tba->name = malloc(strlen(cbuff) + 1);
            memcpy(tba->name, cbuff, strlen(cbuff) + 1);
            tba->type = DNS_RRT_AAAA;
            tba->cls = DNS_RCLS_IN;
            tba->ttl = -1; // unsigned to max
            tba->rdlength = 16;
            tba->rdata = malloc(16);
            tba->next = NULL;
            memset(tba->rdata, 0, 16);
            uv_inet_pton(AF_INET6, cipbuff, tba->rdata); // ipv6 readable str to uint_8 str
            // add into resolve
            if (cache_res != NULL)
            {
                while (cache_res->next != NULL)
                    cache_res = cache_res->next;
                cache_res->next = tba;
            }
            else // new reslove
                rbtree_insert(cacheTree, &(KEY){cbuff, DNS_RRT_AAAA}, tba);
        }
    }

    fclose(fp);
    fp = fopen("keep.txt", "r");
    if (fp == NULL)
        return;
    PLOG(LINFO, "[Cache]\tRecover Dns Cache\n");
    keep_lock = 1;
    int ttl, addtime;
    while (fscanf(fp, "%s", cbuff) != EOF)
    {
        fscanf(fp, "%s", cipbuff);
        fscanf(fp, "%d %d", &ttl, &addtime);
        if (cbuff[strlen(cbuff) - 1] != '.')
        {
            cbuff[strlen(cbuff) + 1] = '\0';
            cbuff[strlen(cbuff)] = '.';
        }
        PLOG(LDEBUG, "[Cache]\tRead host for %s,%s , add at %d, ttl %d\n", cbuff, cipbuff, addtime, ttl);
        if (time(NULL) - addtime > ttl) // expired
            continue;
        if (strrchr(cipbuff, ':') == NULL) // ipv4
        {

            DnsRR *cache_res = rbtree_lookup(cacheTree, &(KEY){cbuff, DNS_RRT_A}),
                  *tba = malloc(sizeof(DnsRR));

            // Construct DnsRR package
            tba->name = malloc(strlen(cbuff) + 1);
            memcpy(tba->name, cbuff, strlen(cbuff) + 1);
            tba->addT = addtime;
            tba->type = DNS_RRT_A;
            tba->cls = DNS_RCLS_IN;
            tba->ttl = ttl; // unsigned to max
            tba->rdlength = 4;
            tba->rdata = malloc(4);
            tba->next = NULL;
            memset(tba->rdata, 0, 4);
            for (int ipi = 0, rdi = 0; ipi < strlen(cipbuff); ipi++) // cover str to ipv4 addr
            {
                if (cipbuff[ipi] == '.' && ++rdi)
                    continue;
                tba->rdata[rdi] = tba->rdata[rdi] * 10 + cipbuff[ipi] - '0';
            }

            // add into resolve
            if (cache_res != NULL)
            {
                while (cache_res->next != NULL)
                    cache_res = cache_res->next;
                cache_res->next = tba;
            }
            else // new reslove
                rbtree_insert(cacheTree, &(KEY){cbuff, DNS_RRT_A}, tba);
        }
        else // ipv6
        {
            DnsRR *cache_res = rbtree_lookup(cacheTree, &(KEY){cbuff, DNS_RRT_AAAA}),
                  *tba = malloc(sizeof(DnsRR));

            // Construct DnsRR package
            tba->name = malloc(strlen(cbuff) + 1);
            memcpy(tba->name, cbuff, strlen(cbuff) + 1);
            tba->addT = addtime;
            tba->type = DNS_RRT_AAAA;
            tba->cls = DNS_RCLS_IN;
            tba->ttl = ttl; // unsigned to max
            tba->rdlength = 16;
            tba->rdata = malloc(16);
            tba->next = NULL;
            memset(tba->rdata, 0, 16);
            uv_inet_pton(AF_INET6, cipbuff, tba->rdata); // ipv6 readable str to uint_8 str
            // add into resolve
            if (cache_res != NULL)
            {
                while (cache_res->next != NULL)
                    cache_res = cache_res->next;
                cache_res->next = tba;
            }
            else // new reslove
                rbtree_insert(cacheTree, &(KEY){cbuff, DNS_RRT_AAAA}, tba);
        }
    }
    keep_lock = 0;
    fclose(fp);

    fp = fopen("keep.txt", "w+"); // clear file
    if (fp == NULL)
        return;
    fclose(fp);
    return;
}

size_t b64_encoded_size(size_t inlen)
{
    size_t ret;
    ret = inlen;
    if (inlen % 3 != 0)
        ret += 3 - (inlen % 3);
    ret /= 3;
    ret *= 4;
    return ret;
}

char *b64_encode(const unsigned char *inBi, size_t len)
{
    char *out;
    size_t elen, i, j, v;

    if (inBi == NULL || len == 0)
        return NULL;

    elen = b64_encoded_size(len);
    out = malloc(elen + 1);
    out[elen] = '\0';

    for (i = 0, j = 0; i < len; i += 3, j += 4)
    {
        v = inBi[i];
        v = i + 1 < len ? v << 8 | inBi[i + 1] : v << 8;
        v = i + 2 < len ? v << 8 | inBi[i + 2] : v << 8;

        out[j] = b64chars[(v >> 18) & 0x3F];
        out[j + 1] = b64chars[(v >> 12) & 0x3F];
        if (i + 1 < len)
            out[j + 2] = b64chars[(v >> 6) & 0x3F];
        else
            out[j + 2] = '=';
        if (i + 2 < len)
            out[j + 3] = b64chars[v & 0x3F];
        else
            out[j + 3] = '=';
    }
    for (int outi = 0; outi < elen; outi++)
    {
        if (out[outi] == '+')
            out[outi] = '-';
        else if (out[outi] == '/')
            out[outi] = '_';
        else if (out[outi] == '=')
            out[outi] = '\0';
    }
    PLOG(LDEBUG, "[Client]\tDNS over HTTPS base64url = %s\n", out);
    return out;
}

size_t curl_wcb(char *ptr, size_t size, size_t nmemb, int *length)
{
    size_t realsize = size * nmemb;
    memcpy(packet_res_buffer + (*length), ptr, realsize);
    *length += realsize;
    return realsize;
}

int curl_query_doh(const unsigned char *inBi, size_t len)
{
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    char *raw_base64url = b64_encode(inBi, len);
    int length = 0;
    if (curl)
    {
        char query_str[DNS_MAX_PACK_SIZE]; // = "https://dns.alidns.com/dns-query?dns=";
        memcpy(query_str, DOT_SERVER, strlen(DOT_SERVER));
        strncpy(query_str + strlen(DOT_SERVER), raw_base64url, strlen(raw_base64url));
        query_str[strlen(DOT_SERVER) + strlen(raw_base64url)] = '\0';
        PLOG(LDEBUG, "[Client]\tCurl Handle URL %s\n", query_str);
        free(raw_base64url);
        struct curl_slist *host_list_ = curl_slist_append(NULL, "cloudflare-dns.com:443:104.16.248.249");
        curl_easy_setopt(curl, CURLOPT_RESOLVE, host_list_);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1);
        curl_easy_setopt(curl, CURLOPT_URL, query_str);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_wcb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &length);

        res = curl_easy_perform(curl);
        packet_res_buffer[length] = '\0';
        PLOG(LDEBUG, "[Client]\tCurl Handle Length %d\n", length);
        print_dns_raw(packet_res_buffer, length);

        /* Check for errors */
        if (res != CURLE_OK)
        {
            PLOG(LCRITICAL, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            curl_easy_cleanup(curl);
            return -1;
        }

        /* always cleanup */
        curl_easy_cleanup(curl);
    }
    return length;
}

DnsRR *check_cache(int qtype, const char *domain_name)
{
    PLOG(LINFO, "[Cache]\tQuery cache for %s type %d\n", domain_name, qtype);
    DnsRR *cache_res = rbtree_lookup(cacheTree, (void *)&(KEY){domain_name, qtype});
    if (cache_res == NULL)
        return NULL;

    if (time(NULL) - cache_res->addT > cache_res->ttl && cache_res->ttl != (uint32_t)(-1))
    {
        PLOG(LINFO, "[Cache]\tTIMEOUT!");
        delete_cache(qtype, domain_name);
        return NULL;
    }

    PLOG(LINFO, "[Cache]\tHIT!\n");
    DnsRR *ret = malloc(sizeof(DnsRR)), *temp = ret;
    while (cache_res->next != NULL)
    {
        dnsRRdcpy(cache_res, temp);
        cache_res = cache_res->next;
        temp->next = malloc(sizeof(DnsRR));
        temp = temp->next;
    }
    dnsRRdcpy(cache_res, temp);
    return ret;
}

void writeRR2file(const DnsRR *rr)
{
    FILE *fp = fopen("keep.txt", "a");
    char addr_readable[128];
    while (rr != NULL)
    {
        if (rr->type != DNS_RRT_A && rr->type != DNS_RRT_AAAA)
        {
            rr = rr->next;
            continue;
        }
        if (rr->type == DNS_RRT_A) //v4
        {
            uv_inet_ntop(AF_INET, rr->rdata, addr_readable, 128);
            fprintf(fp, "%s %s %d %d\n", rr->name, addr_readable, rr->ttl, rr->addT);
        }
        else //v6
        {
            uv_inet_ntop(AF_INET6, rr->rdata, addr_readable, 128);
            fprintf(fp, "%s %s %d %d\n", rr->name, addr_readable, rr->ttl, rr->addT);
        }
        fflush(fp);
        rr = rr->next;
    }
    if (fp == NULL)
        return;
    fclose(fp);
    return;
}

void add_cache(int qtype, const char *domain_name, const DnsRR *dnsRR)
{
    PLOG(LINFO, "[Cache]\tAdd cache for %s type %d\n", domain_name, qtype);
    DnsRR *ret = malloc(sizeof(DnsRR)), *temp = ret;
    writeRR2file(dnsRR);
    while (dnsRR->next != NULL)
    {
        dnsRRdcpy(dnsRR, temp);
        temp->addT = time(NULL);
        dnsRR = dnsRR->next;
        temp->next = malloc(sizeof(DnsRR));
        temp = temp->next;
    }
    dnsRRdcpy(dnsRR, temp);
    rbtree_insert(cacheTree, (void *)&(KEY){domain_name, qtype}, ret);
    return;
}

void delete_cache(int qtype, const char *domain_name)
{
    PLOG(LINFO, "[Cache]\tDelete cache for %s type %d\n", domain_name, qtype);
    DnsRR *cache_res = rbtree_lookup(cacheTree, (void *)&(KEY){domain_name, qtype}), *temp;
    while (cache_res != NULL)
    {
        free(cache_res->rdata);
        free(cache_res->name);
        temp = cache_res;
        cache_res = cache_res->next;
        free(temp);
    }
    rbtree_remove(cacheTree, (void *)&(KEY){domain_name, qtype});
    return;
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
        PLOG(LCRITICAL, "[Client]\tDetected %s trans error or null trans, len :%d !\n", ipaddr, nread);
        return;
    }
    uv_close((uv_handle_t *)handle, close_cb);
    PLOG(LINFO, "[Client]\treceive relay message from: %s, length: %d\n", ipaddr, nread);
    print_dns_raw(rcvbuf->base, nread);

    memcpy(packet_res_buffer, rcvbuf->base, nread);
    flag = nread;
    return;
}

static void cl_send_cb(uv_udp_send_t *req, int status)
{
    PLOG(LDEBUG, "[Client]\tStart Client Send callback\n");
    uv_udp_recv_start(req->handle, alloc_cb, cl_recv_cb);
    return;
}

int dns_client_init()
{
    // send & listen
    PLOG(LINFO, "[Client]\tStart init client.\n");
    uv_ip4_addr("0.0.0.0", 0, &addr);
    uv_udp_init(client_loop, &send_socket);
    uv_udp_bind(&send_socket, (const struct sockaddr *)&addr, UV_UDP_REUSEADDR);
    uv_udp_set_broadcast(&send_socket, 1); // libuv通过0.0.0.0发数据的权限限制，如果不加会异常
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
    req_pack->header.arcount = (ENABLE_DNSOPT > 0); // DNS OPT
    return req_pack;
}

DnsRR *query_RR_init(const char *qname, cshort qtype, cshort qclass)
{
    DnsRR *qd_RR = (DnsRR *)malloc(sizeof(DnsRR));
    qd_RR->name = (char *)malloc(strlen(qname) + 1);
    strncpy(qd_RR->name, qname, strlen(qname));
    qd_RR->name[strlen(qname)] = '\0';
    PLOG(LDEBUG, "[Client]\tQuery RR name :%s\n", qd_RR->name);
    qd_RR->type = qtype;
    qd_RR->cls = qclass;
    qd_RR->next = NULL;

    if (!ENABLE_DNSOPT)
        return qd_RR;
    // DNS OPT
    DnsRR *eRR = (qd_RR->next) = (DnsRR *)malloc(sizeof(DnsRR));
    eRR->name = malloc(1);
    eRR->name[0] = '\0';
    eRR->type = DNS_RRT_OPT;
    eRR->cls = 512;
    eRR->ttl = 0;
    eRR->rdlength = 12;
    eRR->next = NULL;
    char *temptr = eRR->rdata = malloc(12);
    // EDNS https://www.cnblogs.com/cobbliu/p/3188632.html
    *(uint16_t *)temptr = htons(8); // (Defined in [RFC6891]) OPTION-CODE, 2 octets, for ECS is 8 (0x00 0x08).
    temptr += 2;
    *(uint16_t *)temptr = htons(8); //OPTION-LENGTH： 2个字节，描述它之后的内容长度(BYTE)
    temptr += 2;
    *(uint16_t *)temptr = htons(1); //FAMILY： 2个字节，1表示ipv4, 2表示ipv6
    temptr += 2;
    *(uint16_t *)temptr = htons((24 << 8)); // SOURCE|SCOPE NETMASE
    temptr += 2;
    *(uint32_t *)temptr = htonl((((((116 << 8) + 53) << 8) + 237) << 8) + 85);
    return qd_RR;
}

void dns_client_run()
{
    dns_client_init();
    uv_ip4_addr(DNS_SERVER, 53, &send_addr);
    int r = uv_udp_send(&client_req, &send_socket, &client_buf, 1, &send_addr, cl_send_cb);
    uv_run(client_loop, UV_RUN_DEFAULT);
    PLOG(LDEBUG, "[Client]\tuv_udp_send %s\n", r ? "NOERR" : uv_strerror(r));
    return;
}

DnsQRes *query_res(const int type, const char *domain_name)
{
    // Init packet data
    puts("Query Res");
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
        if (ENABLE_EXP)
            qd_packet->records = query_RR_init(domain_name, type, DNS_RCLS_IN);
        else
            return NULL;
        break;
    }
    print_dns_packet(qd_packet);
    char *bias = _dns_encode_packet(packet_raw_buffer, qd_packet);

    // Debug infomation
    PLOG(LDEBUG, "[Client]\tCache miss for %s, send for more infomation\n", domain_name);
    print_dns_raw(packet_raw_buffer, bias - packet_raw_buffer);

    // Prepare sending data
    int data_len = bias - packet_raw_buffer, time_cnt = 0;
    client_buf = uv_buf_init(packet_raw_buffer, data_len);

    // Sending & Waiting (multi-thread)
    if (ENABLE_DOT)
        flag = curl_query_doh(packet_raw_buffer, data_len);
    if (!ENABLE_DOT || flag == -1)
    {
        uv_thread_t client_id;
        flag = 0; // in main threads for sync
        uv_thread_create(&client_id, dns_client_run, NULL);
        while (time_cnt++ < 400 && !flag) // wait for query finish, timeout
            usleep(5 * 1000);             // us -> ms
        if (time_cnt > 400)               // 400 *5 = 2000ms
        {
            PLOG(LWARN, "[Client]\tTimeout\n");
            return NULL;
        }
    }

    // Handle Results
    char *raw_pack = (char *)malloc(flag * sizeof(char));
    DnsPacket *req_packet = (DnsPacket *)malloc(sizeof(DnsPacket));
    memcpy(raw_pack, packet_res_buffer, flag);
    _dns_decode_packet(raw_pack, req_packet); // has free raw_pack
    print_dns_packet(req_packet);

    // Get RR_Res & free mem
    DnsRR *now_rr = req_packet->records, *tempRR;
    DnsQRes *result = malloc(sizeof(DnsQRes));
    for (int i = 0; i < req_packet->header.qdcount; i++)
    {
        tempRR = now_rr->next;
        free(now_rr);
        now_rr = tempRR;
    }
    result->rr = now_rr;
    result->rcode = req_packet->header.rcode;
    // while (now_rr != NULL)
    // {
    //     if (now_rr->type == DNS_RRT_A && now_rr->rdata != NULL && (*(int *)now_rr->rdata) == 0)
    //     {
    //         result->rcode = DNS_RCODE_NXDOMAIN;
    //         break;
    //     }
    //     now_rr = now_rr->next;
    // }
    if (result->rcode == DNS_RCODE_NOERR)
        add_cache(type, domain_name, result->rr);
    free(req_packet);

    return result;
}

DnsQRes *query_A_res(const char *domain_name)
{
    DnsRR *cacheRR = check_cache(DNS_RRT_A, domain_name);
    if (cacheRR != NULL)
    {
        DnsQRes *result = malloc(sizeof(DnsQRes));
        result->rr = cacheRR;
        result->rcode = DNS_RCODE_NOERR;
        while (cacheRR != NULL)
        {
            if (cacheRR->type == DNS_RRT_A && cacheRR->rdata != NULL && (*(int *)cacheRR->rdata) == 0)
            {
                result->rcode = DNS_RCODE_NXDOMAIN;
                break;
            }
            cacheRR = cacheRR->next;
        }
        return result;
    }
    else
        return query_res(DNS_RRT_A, domain_name);
}

DnsQRes *query_AAAA_res(const char *domain_name)
{
    DnsRR *cacheRR = check_cache(DNS_RRT_AAAA, domain_name);
    if (cacheRR != NULL)
    {
        DnsQRes *result = malloc(sizeof(DnsQRes));
        result->rr = cacheRR;
        result->rcode = DNS_RCODE_NOERR;
        return result;
    }
    else
        return query_res(DNS_RRT_AAAA, domain_name);
}

DnsQRes *query_CNAME_res(const char *domain_name)
{
    DnsRR *cacheRR = check_cache(DNS_RRT_CNAME, domain_name);
    if (cacheRR != NULL)
    {
        DnsQRes *result = malloc(sizeof(DnsQRes));
        result->rr = cacheRR;
        result->rcode = DNS_RCODE_NOERR;
        return result;
    }
    else
        return query_res(DNS_RRT_CNAME, domain_name);
}

DnsQRes *query_exp_res(const int type, const char *domain_name)
{
    DnsRR *cacheRR = check_cache(type, domain_name);
    if (cacheRR != NULL)
    {
        DnsQRes *result = malloc(sizeof(DnsQRes));
        result->rr = cacheRR;
        result->rcode = DNS_RCODE_NOERR;
        return result;
    }
    else
        return query_res(type, domain_name);
}