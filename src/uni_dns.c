/*
 * @Author: Makiras
 * @Date: 2020-08-06 11:26:07
 * @LastEditTime: 2020-08-06 17:46:02
 * @LastEditors: Makiras
 * @Description: 
 * @FilePath: \makiras_dns_refact\uni_dns.c
 * @Licensed under the Apache License, Version 2.0 (the "License");
 * @Copyright 2020 @Makiras
 */

#include "uni_dns.h"
#include <string.h>

char *_read_uint16(char *ptr, uint16_t *value)
{
    *value = ntohs(*(uint16_t *)ptr);
    return ptr + 2;
}

char *_write_uint16(char *ptr, uint16_t value)
{
    *(uint16_t *)ptr = htons(value);
    return ptr + 2;
}

char *_read_uint32(char *ptr, uint32_t *value)
{
    *value = ntohl(*(uint32_t *)ptr);
    return ptr + 4;
}

char *_write_uint32(char *ptr, uint32_t value)
{
    *(uint32_t *)ptr = htonl(value);
    return ptr + 4;
}

char *decode_RR_name(char *raw_pack, char **rrn_ptr)
{
    char *rname = (char *)malloc(sizeof(uint8_t) * DNS_NSD_LEN_CNAME);
    char *now_ptr = *rrn_ptr;

    // determine if there is pointer compression
    int is_compression = 0;

    char *current_name_ptr = rname;
    int length = 0; // to computer returned rrn_ptr
    while (*now_ptr != 0)
    {
        if (*(now_ptr)&0xc0)
        {
            now_ptr = raw_pack + (((uint16_t)((uint16_t)((*now_ptr) & 0x3f)) << 8) + (*(now_ptr + 1))); // big-endian
            is_compression = 1;
        }

        int fragment_length = *now_ptr++;
        if (!is_compression)
        {
            length += fragment_length + 1;
        }
        memcpy(current_name_ptr, now_ptr, fragment_length);
        current_name_ptr += fragment_length;
        *current_name_ptr++ = '.';
        now_ptr += fragment_length;
    }
    *current_name_ptr = '\0';

    // modify rrn_ptr
    if (is_compression)
        *rrn_ptr = (*rrn_ptr) + 2 + length;
    else
        *rrn_ptr = now_ptr + 1;
    //puts(rname);
    return rname;
}

char *encode_RR_name(char *raw_ptr, char *name_ptr)
{
    int length = strlen(name_ptr);
    *raw_ptr = '.';
    memcpy(raw_ptr + 1, name_ptr, length + 1);
    uint8_t fragment_length = 0; //such as len('www') or len('com') , etc
    char *ptr = raw_ptr + length;
    while (ptr != raw_ptr - 1)
    {
        if (*ptr == '.')
        {
            (*ptr) = (uint8_t)fragment_length;
            fragment_length = 0;
        }
        else
            fragment_length += 1;
        ptr--;
    }
    return raw_ptr + length + 1;
}

// Free raw pack data after decode
void _dns_decode_packet(char *raw_pack, DnsPacket *packet)
{
    char *now_ptr = raw_pack; // Iter raw packet from begin
    now_ptr = _dns_decode_header(now_ptr, &(packet->header));
    packet->records = NULL;
    int rr_count = packet->header.qdcount + packet->header.ancount + packet->header.nscount + packet->header.arcount,
        tp_qdc = packet->header.qdcount;
    DnsRR *now_rr;
    while (rr_count--) // Iter raw packet and append RRs
    {
        PLOG(LDEBUG, "[UNI]\tRescours Records tbd: %d\n", rr_count);
        DnsRR *rr = (DnsRR *)malloc(sizeof(DnsRR));
        PLOG(LALL, "[UNI]\traw_pack: 0x%08x, now_ptr: 0x%08x\n", raw_pack, now_ptr);
        now_ptr = _dns_decode_RR(raw_pack, now_ptr, rr, tp_qdc > 0);
        if (packet->records != NULL) // use link table store rrs
            now_rr->next = rr;
        else
            packet->records = rr;
        now_rr = rr;
        tp_qdc--;
        print_dns_packet(packet);
    }
    PLOG(LDEBUG, "[UNI]\t_dns_decode_packet free\n");
    free(raw_pack);
    PLOG(LDEBUG, "[UNI]\t_dns_decode_packet END\n");
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

char *_dns_decode_RR(char *raw_pack, char *rr_ptr, DnsRR *rr, int is_qd)
{
    char *now_ptr = rr_ptr;
    PLOG(LALL, "[UNI]\traw_pack: 0x%08x, now_ptr: 0x%08x\n", raw_pack, now_ptr);
    // print_dns_raw(now_ptr-8, 16);
    rr->name = decode_RR_name(raw_pack, &now_ptr);
    rr->next = NULL;
    PLOG(LDEBUG, "[UNI]\tDecode RR name: %s\n", rr->name);
    now_ptr = _read_uint16(now_ptr, &(rr->type));
    now_ptr = _read_uint16(now_ptr, &(rr->cls));
    if (is_qd)
    {
        PLOG(LDEBUG, "[UNI]\tQuery Resource Records, next\n");
        rr->ttl = -1;
        rr->rdlength = -1;
        rr->rdata = NULL;
        return now_ptr;
    }
    now_ptr = _read_uint32(now_ptr, &(rr->ttl));
    now_ptr = _read_uint16(now_ptr, &(rr->rdlength));
    if (rr->rdlength == 0)
        return now_ptr;
    rr->rdata = (uint8_t *)malloc(sizeof(uint8_t) * rr->rdlength);
    memcpy(rr->rdata, now_ptr, rr->rdlength);
    return now_ptr + rr->rdlength;
}

// Free packet data after encode
char *_dns_encode_packet(char *raw_pack, DnsPacket *packet)
{
    char *now_ptr = raw_pack;
    DnsRR *rr_ptr = packet->records, *rr_temp_ptr;
    now_ptr = _dns_encode_header(now_ptr, &(packet->header));
    int rr_count = packet->header.qdcount + packet->header.ancount + packet->header.nscount + packet->header.arcount;
    while (rr_count--)
    {
        PLOG(LALL, "[UNI]\trrcount :%d , rr_ptr 0x%08x\n", rr_count, rr_ptr);
        rr_temp_ptr = rr_ptr->next;
        now_ptr = _dns_encode_RR(now_ptr, rr_ptr, (int16_t)packet->header.qdcount > 0); // Free RR
        rr_ptr = rr_temp_ptr;
        packet->header.qdcount--;
    }
    free(packet);
    return now_ptr;
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

char *_dns_encode_RR(char *raw_pack_ptr, DnsRR *rr, int is_qd)
{
    char *raw_ptr = raw_pack_ptr;
    raw_ptr = encode_RR_name(raw_ptr, rr->name);
    free(rr->name);
    raw_ptr = _write_uint16(raw_ptr, rr->type);
    raw_ptr = _write_uint16(raw_ptr, rr->cls);
    if (is_qd)
        return raw_ptr;
    raw_ptr = _write_uint32(raw_ptr, rr->ttl);
    raw_ptr = _write_uint16(raw_ptr, rr->rdlength);
    if (rr->rdlength == 0)
    {
        free(rr);
        return raw_ptr;
    }
    memcpy(raw_ptr, rr->rdata, rr->rdlength);
    free(rr->rdata);

    return raw_ptr + rr->rdlength;
}

void dnsRRdcpy(const DnsRR *src, DnsRR *dst)
{
    *dst = *src;
    dst->name = malloc(strlen(src->name) + 1);
    dst->rdata = malloc(src->rdlength);
    memcpy(dst->name, src->name, strlen(src->name) + 1);
    memcpy(dst->rdata, src->rdata, src->rdlength);
    return;
}

void print_dns_header(const DnsHeader *header)
{
    PLOG(LDEBUG, "[UNI]\tID: %d\n", header->id);
    PLOG(LDEBUG, "[UNI]\tQR: %d # OpCode: %d # AA: %d # TC: %d \n", header->qr, header->opcode, header->aa, header->tc);
    PLOG(LDEBUG, "[UNI]\tRD: %d # RA: %d # Rcode: %d\n", header->rd, header->ra, header->rcode);
    PLOG(LDEBUG, "[UNI]\tCOUNT qd: %d # an: %d # ns: %d # ar:%d \n", header->qdcount, header->ancount, header->nscount, header->arcount);
    return;
}

void print_dns_RR(const DnsRR *records)
{
    PLOG(LDEBUG, "[UNI]\t------ RR ------\n");
    PLOG(LDEBUG, "[UNI]\tName: %s\n", records->name);
    PLOG(LDEBUG, "[UNI]\tType: %d\n", records->type);
    PLOG(LDEBUG, "[UNI]\tClass: %d\n", records->cls);
    PLOG(LDEBUG, "[UNI]\tTTL: %d\n", records->ttl);
    PLOG(LDEBUG, "[UNI]\trdlenght: %d\n", records->rdlength);
    PLOG(LDEBUG, "[UNI]\t----------------\n");
    return;
}

void print_dns_packet(const DnsPacket *packet)
{
    PLOG(LDEBUG, "[UNI]\t##### DNS PACK #####\n");
    print_dns_header(&(packet->header));
    DnsRR *now_rr = packet->records;
    while (now_rr != NULL)
    {
        print_dns_RR(now_rr);
        now_rr = now_rr->next;
    }
    PLOG(LDEBUG, "[UNI]\t##### PACK END #####\n");
    return;
}

void print_dns_raw(const char *raw_ptr, const int len)
{
    if (PLOG(LDEBUG, "[UNI]\t------ RAW CHAR ------"))
        return;
    for (int i = 0; i < len; i++)
    {
        if (i % 16 == 0)
            printf("\n%04hhx ", i);
        printf("%02hhx ", raw_ptr[i]);
    }
    printf("\n%04hhx\n", len - 1);
    PLOG(LDEBUG, "[UNI]\t------ END  RAW ------\n");
    return;
}