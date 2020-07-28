/*
 * @Description: 
 * @Author: Makiras
 * @Date: 2020-07-27 15:37:28
 * @LastEditors: Makiras
 * @LastEditTime: 2020-07-28 15:52:39
 * @FilePath: /makiras_dns_refact/uni_dns.h
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

// DNS namespace definition max length
cint DNS_NSD_LEN_A = 4;
cint DNS_NSD_LEN_AAAA = 16;
cint DNS_NSD_LEN_CNAME = 256;
cint DNS_MAX_LEN_OPT = 256; // 仍待确认

// DNS packet max size
cint DNS_MAX_INPACK_SIZE = 2048; // 仍待确认
cint DNS_MAX_PACK_SIZE = 5120;   // 仍待确认
cint DNS_DEFAULT_PACK_SIZE = 512;

// DNS Resource Record Part
cshort DNS_RRP_QD = 0;
cshort DNS_RRP_AN = 1;
cshort DNS_RRP_NS = 2;
cshort DNS_RRP_AR = 3;
cshort DNS_RRP_OPT = 4;
cshort DNS_RRP_ITER_END = 5;

// Name Standard [link](http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)

// EDNS ipaddr type
cshort EDNS_ADDR_FAMILY_V4 = 1;
cshort EDNS_ADDR_FAMILY_V6 = 2;

// DNS QR TYPE (1 bit)
cshort DNS_QR_QUERY = 0;
cshort DNS_QR_ANSWER = 1;

// DNS Opcode (4 bit)
cshort DNS_OPC_QUERY = 0;
cshort DNS_OPC_IQUERY = 1;
cshort DNS_OPC_STATUS = 2;
cshort DNS_OPC_UPDATE = 5;

/*
 Authoritative Answer (1 bit)
 Truncation (1 bit)
 Recursion Desired (1 bit)
 Recursion Available (1 bit)
 Z must be 0 (3 bit)
*/

// DNS Response Code (4 bit)
cshort DNS_RCODE_NOERR = 0;
cshort DNS_RCODE_FORMERR = 1;
cshort DNS_RCODE_SERVFAIL = 2;
cshort DNS_RCODE_NXDOMAIN = 3;
cshort DNS_RCODE_NOTIMP = 4;
cshort DNS_RCODE_REFUSED = 5;
cshort DNS_RCODE_YXDOMAIN = 6;
cshort DNS_RCODE_YXRRSET = 7;
cshort DNS_RCODE_NXRRSET = 8;
cshort DNS_RCODE_NOTAUTH = 9;
cshort DNS_RCODE_NOTZONE = 10;
cshort DNS_RCODE_BADVERS = 16; // For OPT(Edns)

// DNS Resource Record Type (16 bit)
cshort DNS_RRT_A = 1;
cshort DNS_RRT_NS = 2;
cshort DNS_RRT_CNAME = 5;
cshort DNS_RRT_SOA = 6;
cshort DNS_RRT_PTR = 12;
cshort DNS_RRT_AAAA = 28;
cshort DNS_RRT_OPT = 41;
cshort DNS_RRT_ALL = 255;

// DNS Resource Record Class (16 bit)
cshort DNS_RCLS_IN = 1;
cshort DNS_RCLS_ANY = 255;

// DNS Edns-client-subnet RDATA
cshort DNS_OPT_CODE_ECS = 8;
cshort DNS_OPT_CODE_KEEPALIVE = 11;
cshort DNS_OPT_CODE_ALL = 255;

// DNS Header Object
struct dns_header
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
};

// DNS Resource Record Object
struct dns_rr
{
  dns_rr* next = NULL;
  uint16_t len;
  uint16_t* name;  // dynamic length name
  uint16_t type;   // Resource Record Type (16 bit)
  uint16_t cls;
  uint32_t ttl;
  uint16_t rdlength; // rdata length in
  uint16_t* rdata;  // rdata
};

// DNS Packet(Logical)
struct dns_packet
{
  dns_header header;
  dns_rr* records;
};

typedef struct dns_packet DnsPacket;
typedef struct dns_header DnsHeader;
typedef struct dns_rr DnsRR;

/*
  Decode:
    Decode from raw bytestream, using ntohs() convert and using ptr* iter the RAW PACK
  Encode:
    Encode from readable struct, using htons() convert and using ptr* to append behind the RAW_PACK
*/


// Decode/Encode RAW&packet
char* _dns_decode_packet(char* raw_pack, DnsPacket* packet);
int _dns_encode_packet(char* raw_pack, DnsPacket* packet);

// Decode/Endcode RAW&Header
char* _dns_decode_header(char* pack_ptr,DnsHeader* header);
int _dns_encode_header(char* pack_ptr,DnsHeader* header);

// Decode/Endcode RAW&RR
char* _dns_decode_RR(char* rr_ptr,DnsRR* rr);
int _dns_encode_RR(char* rr_ptr,DnsRR* rr);

#endif