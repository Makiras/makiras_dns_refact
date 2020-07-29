/*
 * @Description: 
 * @Author: Makiras
 * @Date: 2020-07-28 15:36:51
 * @LastEditors: Makiras
 * @LastEditTime: 2020-07-29 17:51:45
 * @FilePath: /makiras_dns_refact/uni_dns.c
 */

#include <string.h>
#include "uni_dns.h"

char *_read_uint16(char *ptr, uint16_t *value)
{
    value = ntohs(*(uint16_t *)ptr);
    return ptr + 2;
}

char *_write_uint16(char *ptr, uint16_t value)
{
    *(uint16_t *)ptr = htons(value);
    return ptr + 2;
}

char *_read_uint32(char *ptr, uint32_t *value)
{
    value = ntohl(*(uint32_t *)ptr);
    return ptr + 4;
}

char *_write_uint32(char *ptr, uint32_t value)
{
    *(uint32_t *)ptr = htonl(value);
    return ptr + 4;
}

char *decode_RR_name(char **rrn_ptr)
{
    char *rname = (char *)malloc(sizeof(uint8_t) * DNS_NSD_LEN_CNAME);
    char *now_ptr = *rrn_ptr;
    // todo: read name & write name
    return rname;
}

char *encode_RR_name(char *raw_ptr, char *name_ptr)
{
    // todo: encode rr name, WATCH: byte order, bits%16 = 0;
    return raw_ptr;
}

// Free raw pack data after decode
void _dns_decode_packet(char *raw_pack, DnsPacket *packet)
{
    char *now_ptr = raw_pack; // Iter raw packet from begin
    now_ptr = _dns_decode_header(now_ptr, &(packet->header));
    int rr_count = packet->header.qdcount + packet->header.ancount + packet->header.nscount + packet->header.arcount;
    while (rr_count--) // Iter raw packet and append RRs
    {
        DnsRR *rr = (DnsRR *)malloc(sizeof(DnsRR));
        now_ptr = _dns_decode_RR(now_ptr, rr);
        if (packet->records != NULL) // use link table store rrs
            packet->records->next = rr;
        else
            packet->records = rr;
    }
    free(raw_pack);
    return; // End at packet end
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
    rr->name = decode_RR_name(&now_ptr);
    now_ptr = _read_uint16(now_ptr, &(rr->type));
    now_ptr = _read_uint16(now_ptr, &(rr->cls));
    now_ptr = _read_uint32(now_ptr, &(rr->ttl));
    now_ptr = _read_uint16(now_ptr, &(rr->rdlength));
    rr->rdata = (uint8_t *)malloc(sizeof(uint8_t) * rr->rdlength);
    strncpy(rr->rdata, now_ptr, rr->rdlength);
    return now_ptr + (rr->rdlength);
}

// Free packet data after encode
void _dns_encode_packet(char *raw_pack, DnsPacket *packet)
{
    char *now_ptr = raw_pack;
    DnsRR *rr_ptr = packet->records, *rr_temp_ptr;
    now_ptr = _dns_encode_header(now_ptr, &(packet->header));
    int rr_count = packet->header.qdcount + packet->header.ancount + packet->header.nscount + packet->header.arcount;
    while (rr_count--)
    {
        rr_temp_ptr = rr_ptr->next;
        now_ptr = _dns_encode_RR(now_ptr, rr_ptr); // Free RR
        rr_ptr = rr_temp_ptr;
    }
    free(packet);
    return;
}

char *_dns_encode_header(char *raw_pack_ptr, DnsHeader *header)
{
    char *raw_ptr = raw_pack_ptr;
    uint16_t status_codes = 0;
    raw_ptr = _write_uint16(raw_ptr, header->id);
    status_codes |= (header->qr & 1) << 15;
    status_codes |= (header->opcode & 0xF) << 11;
    status_codes |= (header->aa & 1) << 10;
    status_codes |= (header->tc & 1) << 9;
    status_codes |= (header->rd & 1) << 8;
    status_codes |= (header->ra & 1) << 7;
    status_codes |= header->rcode & 0xF;
    raw_ptr = _write_uint16(raw_ptr, status_codes);
    raw_ptr = _write_uint16(raw_ptr, header->qdcount);
    raw_ptr = _write_uint16(raw_ptr, header->ancount);
    raw_ptr = _write_uint16(raw_ptr, header->nscount);
    raw_ptr = _write_uint16(raw_ptr, header->arcount);
    return raw_ptr;
}

char *_dns_encode_RR(char *raw_pack_ptr, DnsRR *rr)
{
    char *raw_ptr = raw_pack_ptr;
    raw_ptr = encode_RR_name(raw_ptr, rr->name);
    raw_ptr = _write_uint16(raw_ptr, rr->type);
    raw_ptr = _write_uint16(raw_ptr, rr->cls);
    raw_ptr = _write_uint32(raw_ptr, rr->ttl);
    raw_ptr = _write_uint16(raw_ptr, rr->rdlength);
    strncpy(raw_ptr, rr->rdata, rr->rdlength);
    free(rr->rdata);
    free(rr->name);
    free(rr);
    return raw_ptr;
}