/*
 * @Description: 
 * @Author: Makiras
 * @Date: 2020-07-28 15:36:51
 * @LastEditors: Makiras
 * @LastEditTime: 2020-07-28 23:59:52
 * @FilePath: /makiras_dns_refact/uni_dns.c
 */

#include "uni_dns.h"

char *_read_uint16(char *ptr, uint16_t *value)
{
    value = ntohs(*(uint16_t *)ptr);
    return ptr + 2;
}

char *_dns_decode_packet(char *raw_pack, DnsPacket *packet)
{
    char *now_ptr = raw_pack; // Iter raw packet from begin
    now_ptr = _dns_decode_header(now_ptr, &(packet->header));
    while (now_ptr != NULL) // Iter raw packet and append RRs
    {
    }

    return now_ptr; // End at packet end
}

char *_dns_decode_header(char *header_ptr, DnsHeader *header)
{
    char *now_prt = header_ptr; // Iter header from header begin
    uint16_t status_codes;
    now_prt = _read_uint16(now_prt, &(header->id));
    now_prt = _read_uint16(now_prt, &status_codes);
    /*
        LE: 0x1         0x2
            ---Rcode QR----- (QR at 15bit, Rcode at 4bit)
        BE: 0x1         0x2
            QR---------RCODE (QR at 15bit, Rcode at 4bit)
    */
    header->qr = status_codes >> 15;
    header->opcode = (status_codes >> 11) & 0xF;
    header->aa = (status_codes >> 10) & 1;
    header->tc = (status_codes >> 9) & 1;
    header->rd = (status_codes >> 8) & 1;
    header->ra = (status_codes >> 7) & 1;
    header->rcode = status_codes & 0xF;
    now_prt = _read_uint16(now_prt, &(header->qdcount));
    now_prt = _read_uint16(now_prt, &(header->ancount));
    now_prt = _read_uint16(now_prt, &(header->nscount));
    now_prt = _read_uint16(now_prt, &(header->arcount));
    return now_prt; // End at header end
}

char *_dns_decode_RR(char *rr_ptr, DnsRR *rr)
{
    char *now_ptr = rr_ptr;
    return now_ptr;
}