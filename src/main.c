#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns_client.h"
#include "udefine.h"
#include "uni_dns.h"

uv_loop_t *loop, *client_loop;
extern uv_udp_t send_socket;
extern uv_udp_t recv_socket;

char *bind_address = "0.0.0.0";

void init_client_loop()
{
    dns_cache_init();
    uv_loop_init(client_loop);
    return;
}

int main()
{
    puts("[INFO] Start Running");
    fflush(stdout);
    uv_thread_t client_id;                                // 客户端线程ID
    loop = uv_default_loop();                             // 服务端loop
    client_loop = malloc(sizeof(uv_loop_t));              // 客户端loop
    uv_thread_create(&client_id, init_client_loop, NULL); // 创建客户端线程
    dns_server_init();
    uv_run(loop, UV_RUN_DEFAULT);
    puts("[INFO] Stop Running");
    return 0;
}