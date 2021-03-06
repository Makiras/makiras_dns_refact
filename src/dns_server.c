#include "dns_server.h"
#include "uni_dns.h"

static uv_udp_t recv_socket, ipv6_recv_socket;
char send_buffer[DNS_MAX_PACK_SIZE];

DnsPacket *handle_dns_req(const char *rcvbuf, const char *ipaddr, const ssize_t nread);

static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    static char slab[DNS_MAX_PACK_SIZE];
    buf->base = slab;
    buf->len = sizeof(slab);
    return;
}

static void close_cb(uv_handle_t *handle)
{
    // uv_is_closing(handle);
}

static void sv_send_cb(uv_udp_send_t *req, int status)
{
    PLOG(LDEBUG, "[Server]\tSend Successful\n");
    // uv_close((uv_handle_t *)req->handle, close_cb);
    // free(req);
}

static void dns_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *rcvbuf, const struct sockaddr *addr, unsigned flags)
{
    uv_udp_send_t *req = malloc(sizeof(uv_udp_send_t)); // 事件处理句柄，类似标识id
    uv_buf_t sndbuf;
    char ipaddr[17] = {0};
    uv_ip4_name(&addr, ipaddr, sizeof(ipaddr));
    if (nread <= 0)
    {
        PLOG(LCRITICAL, "[Server]\tDetected %s trans error or null trans, len :%d !\n", ipaddr, nread);
        return;
    }

    PLOG(LDEBUG, "[Server]\tReceive message from: %s, length: %d\n", ipaddr, nread);
    DnsPacket *results = handle_dns_req(rcvbuf->base, ipaddr, nread);
    char *bias = _dns_encode_packet(send_buffer, results);
    sndbuf = uv_buf_init(send_buffer, bias - send_buffer);
    print_dns_raw(send_buffer, bias - send_buffer);

    uv_udp_send(req, handle, &sndbuf, 1, addr, sv_send_cb);
    return;
}

void packet2response(DnsPacket *origin)
{
    origin->header.qr = DNS_QR_ANSWER;
    // origin->header.rcode = is_support ? DNS_RCODE_NOERR : DNS_RCODE_NOTIMP;
    return;
}

DnsQRes *handle_qd_rr(const DnsRR *rr_ptr)
{
    switch (rr_ptr->type)
    {
    case DNS_RRT_A:
        PLOG(LINFO, "[Server]\tHandel A req for %s\n", rr_ptr->name);
        return query_A_res(rr_ptr->name);
        break;
    case DNS_RRT_NS:
        break;
    case DNS_RRT_CNAME:
        PLOG(LINFO, "[Server]\tHandel CNAME req for %s\n", rr_ptr->name);
        return query_CNAME_res(rr_ptr->name);
        break;
    case DNS_RRT_SOA:
        break;
    case DNS_RRT_PTR:
        PLOG(LINFO, "[Server]\tDO NOT Handel PTR req for %s, SPEED UP\n", rr_ptr->name);
        return NULL;
        break;
    case DNS_RRT_AAAA:
        PLOG(LINFO, "[Server]\tHandel AAAA req for %s\n", rr_ptr->name);
        return query_AAAA_res(rr_ptr->name);
        break;
    case DNS_RRT_ALL:
        break;
    default:
        break;
    }
    if (ENABLE_EXP)
    {
        PLOG(LINFO, "[Server]\tHandel experimental req for %s\n", rr_ptr->name);
        return query_exp_res(rr_ptr->type, rr_ptr->name);
    }

    return NULL;
}

DnsPacket *handle_dns_req(const char *rcvbuf, const char *ipaddr, const ssize_t nread)
{
    PLOG(LINFO, "[Server]\tStart handle DNS Req\n");

    // Debug for receive message
    char *raw_pack = (char *)malloc(nread * sizeof(char));
    DnsPacket *req_packet = (DnsPacket *)malloc(sizeof(DnsPacket));
    memcpy(raw_pack, rcvbuf, nread);
    _dns_decode_packet(raw_pack, req_packet); // free raw_pack
    print_dns_packet(req_packet);

    // Handle recv msg
    DnsRR *now_rr_ptr = req_packet->records, *result_rr = req_packet->records;
    DnsQRes *qr_result;
    while (result_rr->next != NULL)
        result_rr = result_rr->next;
    for (int i = 0; i < req_packet->header.qdcount; i++)
    {
        // Handle add RR
        qr_result = handle_qd_rr(now_rr_ptr);
        if (qr_result != NULL)
        {
            result_rr->next = qr_result->rr;
            while (result_rr->next != NULL)
            {
                result_rr = result_rr->next;
                if (result_rr->type != DNS_RRT_OPT)
                    req_packet->header.ancount++;
                else
                    req_packet->header.arcount++;
            }
            // Handle Rcode
            if (qr_result->rcode != DNS_RCODE_NOERR)
            {
                req_packet->header.rcode = qr_result->rcode;
                break;
            }
        }
        else
        {
            req_packet->header.rcode = DNS_RCODE_SERVFAIL;
            break;
        }

        now_rr_ptr = now_rr_ptr->next;
    }
    if (req_packet->header.rcode == DNS_RCODE_NXDOMAIN)
    {
        now_rr_ptr = req_packet->records;
        for (int i = 0; i < req_packet->header.qdcount - 1; i++)
            now_rr_ptr = now_rr_ptr->next;
        result_rr = now_rr_ptr->next;
        now_rr_ptr->next = NULL;
        while (result_rr != NULL)
        {
            now_rr_ptr = result_rr;
            result_rr = result_rr->next;
            free(now_rr_ptr);
        }
        req_packet->header.ancount = req_packet->header.arcount = 0;
    }

    packet2response(req_packet); //, now_rr_ptr != NULL);

    // Debug handle Result
    PLOG(LINFO, "[Server]\t---------- SENDBACK ------------\n");
    print_dns_packet(req_packet);
    PLOG(LDEBUG, "[Server]\t---------- BACK END ------------\n");

    return req_packet;
}

int dns_server_init()
{
    PLOG(LINFO, "[Server]\tStart Dns Server\n");
    uv_udp_init(loop, &recv_socket);
    struct sockaddr_in recv_addr;
    PLOG(LDEBUG, "[Server]\tBind Addr %s\n", BIND_ADDR);
    uv_ip4_addr(BIND_ADDR, 53, &recv_addr);
    uv_udp_bind(&recv_socket, (const struct sockaddr *)&recv_addr, UV_UDP_REUSEADDR);
    uv_udp_recv_start(&recv_socket, alloc_cb, dns_recv_cb);

    if (BIND_IPV6)
    {
        struct sockaddr_in recv_addr6;
        uv_udp_init(loop, &ipv6_recv_socket);
        uv_ip6_addr("::", 53, &recv_addr6); // local loopback
        uv_udp_bind(&ipv6_recv_socket, (const struct sockaddr *)&recv_addr6, UV_UDP_REUSEADDR);
        uv_udp_recv_start(&ipv6_recv_socket, alloc_cb, dns_recv_cb);
    }
    return 0;
}