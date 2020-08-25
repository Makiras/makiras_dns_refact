/*
 * @Author: Makiras
 * @Date: 2020-08-06 11:26:07
 * @LastEditTime: 2020-08-06 21:40:03
 * @LastEditors: Makiras
 * @Description: 
 * @FilePath: \makiras_dns_refact\src\uni_dns.h
 * @Licensed under the Apache License, Version 2.0 (the "License");
 * @Copyright 2020 @Makiras
 */

/*
    +--+--+--+--+-+ DNS HEADER FORMAT +-+--+--+--+--+

      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

#ifndef _UNI_DNS_H
#define _UNI_DNS_H

#include <stdio.h>
#include "udefine.h"

// DNS Header Object
typedef struct dns_header
{
  uint16_t id;
  uint8_t qr;
  uint8_t opcode;
  uint8_t aa;
  uint8_t tc;
  uint8_t rd;
  uint8_t ra;
  uint16_t rcode;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} DnsHeader;

// DNS Resource Record Object
typedef struct dns_rr
{
  struct dns_rr *next;
  uint16_t len;  // not used for now
  uint8_t *name; // dynamic length name
  uint16_t type; // Resource Record Type (16 bit)
  uint16_t cls;
  uint32_t ttl;
  uint16_t rdlength; // rdata length in
  uint8_t *rdata;    // rdata
} DnsRR;

// DNS Packet(Logical)
typedef struct dns_packet
{
  DnsHeader header;
  DnsRR *records;
} DnsPacket;

/*
  Decode:
    Decode from raw bytestream, using ntohs() convert and using ptr* iter the RAW PACK
  Encode:
    Encode from readable struct, using htons() convert and using ptr* to append behind the RAW_PACK
*/

// Decode/Encode RAW&packet
void _dns_decode_packet(char *raw_pack, DnsPacket *packet);
void _dns_encode_packet(char *raw_pack, DnsPacket *packet);

// Decode/Endcode RAW&Header
char *_dns_decode_header(char *header_ptr, DnsHeader *header);
char *_dns_encode_header(char *raw_ptr, DnsHeader *header);

// Decode/Endcode RAW&RR
char *_dns_decode_RR(char* raw_pack,char *rr_ptr, DnsRR *rr);
char *_dns_encode_RR(char *rr_ptr, DnsRR *rr);

#endif