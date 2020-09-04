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
    uv_loop_init(client_loop);
    return;
}

int main()
{
    puts("[INFO] Start Running");
    fflush(stdout);
    uv_thread_t client_id;
    loop = uv_default_loop();
    client_loop = malloc(sizeof(uv_loop_t));
    uv_thread_create(&client_id, init_client_loop, NULL);
    dns_server_init();
    uv_run(loop, UV_RUN_DEFAULT);
    puts("[INFO] Stop Running");
    return 0;
}