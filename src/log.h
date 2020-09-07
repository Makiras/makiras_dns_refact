#ifndef _LOG_H
#define _LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

enum DEBUG_ENUM
{
    LALL,
    LDEBUG,
    LINFO,
    LWARN,
    LCRITICAL,
    LERROR
};

int PLOG(const int debug_level, const char *fmt, ...);
#endif