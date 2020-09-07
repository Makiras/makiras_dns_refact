/*
 * @Description: Add universal define for Config
 * @Author: Makiras
 * @Date: 2020-07-26 20:47:51
 * @LastEditors: Makiras
 * @LastEditTime: 2020-07-27 16:58:20
 * @FilePath: /makiras_dns/udefine.h
 */ 

#ifndef _UDEFINE_H
#define _UDEFINE_H

#include <stdint.h>
#include "log.h"
#include "config.h"

#define cint const int32_t
#define cLL  const int64_t
#define cfloat const float
#define cdouble const double
#define cshort const int16_t

// DNS namespace definition max length
#define DNS_NSD_LEN_A  4
#define DNS_NSD_LEN_AAAA  16
#define DNS_NSD_LEN_CNAME  256
#define DNS_MAX_LEN_OPT  256 // 仍待确认

// DNS packet max size
#define DNS_MAX_INPACK_SIZE  2048 // 仍待确认
#define DNS_MAX_PACK_SIZE  5120   // 仍待确认
#define DNS_DEFAULT_PACK_SIZE  512

// DNS Resource Record Part
#define DNS_RRP_QD  0
#define DNS_RRP_AN  1
#define DNS_RRP_NS  2
#define DNS_RRP_AR  3
#define DNS_RRP_OPT  4
#define DNS_RRP_ITER_END  5

// Name Standard [link](http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)

// EDNS ipaddr type
#define EDNS_ADDR_FAMILY_V4  1
#define EDNS_ADDR_FAMILY_V6  2

// DNS QR TYPE (1 bit)
#define DNS_QR_QUERY  0
#define DNS_QR_ANSWER  1

// DNS Opcode (4 bit)
#define DNS_OPC_QUERY  0
#define DNS_OPC_IQUERY  1
#define DNS_OPC_STATUS  2
#define DNS_OPC_UPDATE  5

/*
 Authoritative Answer (1 bit)
 Truncation (1 bit)
 Recursion Desired (1 bit)
 Recursion Available (1 bit)
 Z must be 0 (3 bit)
*/

// DNS Response Code (4 bit)
#define DNS_RCODE_NOERR  0
#define DNS_RCODE_FORMERR  1
#define DNS_RCODE_SERVFAIL  2
#define DNS_RCODE_NXDOMAIN  3
#define DNS_RCODE_NOTIMP  4
#define DNS_RCODE_REFUSED  5
#define DNS_RCODE_YXDOMAIN  6
#define DNS_RCODE_YXRRSET  7
#define DNS_RCODE_NXRRSET  8
#define DNS_RCODE_NOTAUTH  9
#define DNS_RCODE_NOTZONE  10
#define DNS_RCODE_BADVERS  16 // For OPT(Edns)

// DNS Resource Record Type (16 bit)
#define DNS_RRT_A  1
#define DNS_RRT_NS  2
#define DNS_RRT_CNAME  5
#define DNS_RRT_SOA  6
#define DNS_RRT_PTR  12
#define DNS_RRT_AAAA  28
#define DNS_RRT_OPT  41
#define DNS_RRT_ALL  255

// DNS Resource Record Class (16 bit)
#define DNS_RCLS_IN  1
#define DNS_RCLS_ANY  255

// DNS Edns-client-subnet RDATA
#define DNS_OPT_CODE_ECS  8
#define DNS_OPT_CODE_KEEPALIVE  11
#define DNS_OPT_CODE_ALL  255

#endif