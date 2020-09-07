#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns_client.h"
#include "udefine.h"
#include "uni_dns.h"

uv_loop_t *loop, *client_loop;
extern uv_udp_t send_socket;

void init_client_loop()
{
    dns_cache_init();
    uv_loop_init(client_loop);
    return;
}

int main()
{
    PLOG(LINFO, "[Main]\tStart Running\n");

    init_config();
    uv_thread_t client_id;                                // 客户端线程ID
    loop = uv_default_loop();                             // 服务端loop
    client_loop = malloc(sizeof(uv_loop_t));              // 客户端loop
    uv_thread_create(&client_id, init_client_loop, NULL); // 创建客户端线程
    dns_server_init();
    uv_run(loop, UV_RUN_DEFAULT);
    PLOG(LINFO, "[Main]\tRunning\n");
    return 0;
}