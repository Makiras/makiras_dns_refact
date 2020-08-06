/*
 * @Author: Makiras
 * @Date: 2020-08-06 11:26:35
 * @LastEditTime: 2020-08-06 20:19:19
 * @LastEditors: Makiras
 * @Description: 
 * @FilePath: \makiras_dns_refact\dns_client.c
 * @Licensed under the Apache License, Version 2.0 (the "License");
 * @Copyright 2020 @Makiras
 */

#include "dns_client.h"

int main() {
    uv_loop_t *loop = (uv_loop_t*)malloc(sizeof(uv_loop_t));
    uv_loop_init(loop);

    printf("Now quitting.\n");
    uv_run(loop, UV_RUN_DEFAULT);

    uv_loop_close(loop);
    free(loop);
    return 0;
}