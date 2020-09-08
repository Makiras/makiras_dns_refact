#include "config.h"
#define MAX_BF_LEN 128

char *DNS_SERVER;
char *DOT_SERVER;
char *BIND_ADDR;
int ENABLE_DOT;
int ENABLE_DNSOPT;
int ENABLE_EXP;
int BIND_IPV6;
int DEBUG_LEVEL;

int init_config()
{
    PLOG(LINFO, "[Config]\tStart Config Loading\n");
    FILE *fp = fopen("config.ini", "r");
    if (fp == NULL)
        return 0;
    char buffer[MAX_BF_LEN], bkey[MAX_BF_LEN], bvalue[MAX_BF_LEN];
    int bindex, bvindex, bmax;
    while (fgets(buffer, MAX_BF_LEN, fp) && !feof(fp))
    {
        bmax = strlen(buffer);
        if (buffer[0] == ';' || buffer[0] == '[' || bmax < 2) // comment or unhandled section
            continue;
        bindex = bvindex = 0;
        // get key
        while (buffer[bindex] != '=' && buffer[bindex] != ' ' && bindex < bmax)
        {
            bkey[bindex] = buffer[bindex];
            bindex++;
        }
        bkey[bindex] = '\0';

        // phaser value
        while (buffer[bindex] == '=' || buffer[bindex] == ' ')
            bindex++;
        int flag_in_str = 0;
        while (buffer[bindex] != '\n' && bindex < bmax)
        {
            if (buffer[bindex] == '"')
            {
                flag_in_str = !flag_in_str;
                bindex++;
                continue;
            }
            if (!flag_in_str && buffer[bindex] == ' ')
            {
                bindex++;
                continue;
            }
            bvalue[bvindex++] = buffer[bindex++];
        }
        bvalue[bvindex] = '\0';
        PLOG(LDEBUG, "[Config]\tkey: [%s] , value: [%s]\n", bkey, bvalue);

        if (strcmp(bkey, "bind_addr") == 0)
        {
            BIND_ADDR = malloc(strlen(bvalue) + 1);
            memcpy(BIND_ADDR, bvalue, strlen(bvalue) + 1);
        }
        else if (strcmp(bkey, "dns_server") == 0)
        {
            DNS_SERVER = malloc(strlen(bvalue) + 1);
            memcpy(DNS_SERVER, bvalue, strlen(bvalue) + 1);
        }
        else if (strcmp(bkey, "dot_server") == 0)
        {
            DOT_SERVER = malloc(strlen(bvalue) + 1);
            memcpy(DOT_SERVER, bvalue, strlen(bvalue) + 1);
        }
        else if (strcmp(bkey, "enable_dot") == 0)
        {
            if (strcmp(bvalue, "true") == 0 || strcmp(bvalue, "1") == 0)
                ENABLE_DOT = 1;
            else
                ENABLE_DOT = 0;
        }
        else if (strcmp(bkey, "enable_dnsopt") == 0)
        {
            if (strcmp(bvalue, "true") == 0 || strcmp(bvalue, "1") == 0)
                ENABLE_DNSOPT = 1;
            else
                ENABLE_DNSOPT = 0;
        }
        else if (strcmp(bkey, "bind_ipv6") == 0)
        {
            if (strcmp(bvalue, "true") == 0 || strcmp(bvalue, "1") == 0)
                BIND_IPV6 = 1;
            else
                BIND_IPV6 = 0;
        }
        else if (strcmp(bkey, "enable_exp") == 0)
        {
            if (strcmp(bvalue, "true") == 0 || strcmp(bvalue, "1") == 0)
                ENABLE_EXP = 1;
            else
                ENABLE_EXP = 0;
        }
        else if (strcmp(bkey, "debug_level") == 0)
        {
            if (strcmp(bvalue, "all") == 0)
                DEBUG_LEVEL = LALL;
            else if (strcmp(bvalue, "debug") == 0)
                DEBUG_LEVEL = LDEBUG;
            else if (strcmp(bvalue, "info") == 0)
                DEBUG_LEVEL = LINFO;
            else if (strcmp(bvalue, "warn") == 0)
                DEBUG_LEVEL = LWARN;
            else if (strcmp(bvalue, "critical") == 0)
                DEBUG_LEVEL = LCRITICAL;
            else if (strcmp(bvalue, "error") == 0)
                DEBUG_LEVEL = LERROR;
            else
                DEBUG_LEVEL = LWARN;
        }
    }

    return 0;
}