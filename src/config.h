#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

static char *DNS_SERVER;
static char *DOT_SERVER;
static int ENABLE_DOT;
static int ENABLE_DNSOPT;
static int BIND_IPV6;
static int DEBUG_LEVEL;

int init_config();

#endif