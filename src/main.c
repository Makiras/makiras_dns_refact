#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pthread.h>

#include "uni_dns.h"
#include "udefine.h"
#include "dns_client.h"

uv_loop_t *loop;
uv_udp_t send_socket;
uv_udp_t recv_socket;
char* bind_address = "0.0.0.0";

int main()
{
    puts("[INFO] Start Running");
    fflush(stdout);
    loop = uv_default_loop();
    dns_server_init();
    uv_run(loop, UV_RUN_DEFAULT);
    puts("[INFO] Stop Running");
    return 0;
}