#include "dns_server.h"
#include "uni_dns.h"

static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    static char slab[DNS_MAX_PACK_SIZE];
    buf->base = slab;
    buf->len = sizeof(slab);
    return;
}

static void close_cb(uv_handle_t* handle)
{
    uv_is_closing(handle);
}

static void sv_send_cb(uv_udp_send_t *req, int status)
{
    uv_close((uv_handle_t *)req->handle, close_cb);
    free(req);
}

static void dns_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *rcvbuf, const struct sockaddr *addr, unsigned flags)
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
    // uv_udp_recv_stop(handle);
    printf("[INFO] receive message from: %s, length: %d\n", ipaddr, nread);
    handle_dns_req(rcvbuf->base, ipaddr, nread);
    fflush(stdout);
    // uv_udp_send(req, handle, &sndbuf, 1, addr, sv_send_cb);
    return;
}

void handle_qd_rr(const DnsRR *rr_ptr)
{
    switch (rr_ptr->type)
    {
    case DNS_RRT_A:
        printf("[Info] Handel A req for %s\n", rr_ptr->name);
        query_A_res(rr_ptr->name);
        break;
    case DNS_RRT_NS:
        /* code */
        break;
    case DNS_RRT_CNAME:
        /* code */
        break;
    case DNS_RRT_SOA:
        /* code */
        break;
    case DNS_RRT_PTR:
        printf("[Info][todo] Handel PTR req for %s\n", rr_ptr->name);
        break;
    case DNS_RRT_AAAA:
        /* code */
        break;
    case DNS_RRT_ALL:
        /* code */
        break;
    default:
        break;
    }
    return;
}

int handle_dns_req(const char *rcvbuf, const char *ipaddr, const ssize_t nread)
{
    char *raw_pack = (char *)malloc(nread * sizeof(char));
    char *temp[5000];
    DnsPacket *req_packet = (DnsPacket *)malloc(sizeof(DnsPacket));
    memcpy(raw_pack, rcvbuf, nread);
    _dns_decode_packet(raw_pack, req_packet);
    print_dns_packet(req_packet);

    DnsRR *now_rr_ptr = req_packet->records;
    for (int i = 0; i < req_packet->header.qdcount; i++)
    {
        handle_qd_rr(now_rr_ptr);
        now_rr_ptr = now_rr_ptr->next;
    }

    _dns_encode_packet(temp, req_packet);
    return 0;
}

int dns_server_init()
{
    uv_udp_init(loop, &recv_socket);
    struct sockaddr_in recv_addr;
    uv_ip4_addr(bind_address, 53, &recv_addr);
    uv_udp_bind(&recv_socket, (const struct sockaddr *)&recv_addr, UV_UDP_REUSEADDR);
    uv_udp_recv_start(&recv_socket, alloc_cb, dns_recv_cb);
    return 0;
}