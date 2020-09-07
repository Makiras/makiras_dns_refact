#include "log.h"
#include "config.h"
#include <time.h>

extern int DEBUG_LEVEL;

char *debug_str[] = {"ALL INFO", "  DEBUG ", "  INFO  ", "  WARN  ", "CRITICAL", "  ERROR "};
int PLOG(const int debug_level, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    if (debug_level < DEBUG_LEVEL) // it's not important
        return 0;

    // get Time
    char tbuf[80];
    time_t now_tmt;
    now_tmt = time(NULL);
    strftime(tbuf, 80, "%H:%M:%S", localtime(&now_tmt));
    printf("%s ", tbuf);

    // print debug info
    printf("[%s]", debug_str[debug_level]);
    vprintf(fmt, args);

    va_end(args);
    fflush(stdout);
    return 0;
}