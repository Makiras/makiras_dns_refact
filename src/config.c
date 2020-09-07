#include "config.h"
#define MAX_BF_LEN 128
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
        while (buffer[bindex] != '=' && buffer[bindex] != ' ' && buffer[bindex] != '\n' && bindex < bmax)
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
        PLOG(LDEBUG, "[Config]\tkey: %s , value: %s\n", bkey, bvalue);
    }

    return 0;
}