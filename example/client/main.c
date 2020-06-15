#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include "../../inc/lcp.h"

#define BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BINARY(byte)  \
	(byte & 0x80 ? '1' : '0'), \
	(byte & 0x40 ? '1' : '0'), \
	(byte & 0x20 ? '1' : '0'), \
	(byte & 0x10 ? '1' : '0'), \
	(byte & 0x08 ? '1' : '0'), \
	(byte & 0x04 ? '1' : '0'), \
	(byte & 0x02 ? '1' : '0'), \
	(byte & 0x01 ? '1' : '0') 


int main(void)
{
	struct lcp_ctx *ctx;
	int running = 1;
	struct sockaddr_in6 addr;
	struct sockaddr *addr_ptr = (struct sockaddr *)&addr;
	int addr_sz = sizeof(addr);

	struct sockaddr_in6 cli;
	char buf[512];
	int len;
	int s;
	int port;

	struct sockaddr_in6 main;
	struct sockaddr_in6 disco;
	struct sockaddr_in6 proxy;
	
	struct sockaddr_in6 peer;
	char flg;
	uint16_t proxy_id;
	short open_port;
	struct lcp_con *con;

	struct lcp_evt evt;
	int i;
	char hnt_flg = 1;

	srand(time(NULL));

	/*
	 * Setup server-addresses for the different servers.
	 */
	memset(&main, 0, addr_sz);
	main.sin6_family = AF_INET6;
	main.sin6_port = htons(4242);
	inet_pton(AF_INET6, "::1", &main.sin6_addr);

	memset(&disco, 0, addr_sz);
	disco.sin6_family = AF_INET6;
	disco.sin6_port = htons(4243);
	inet_pton(AF_INET6, "::1", &disco.sin6_addr);

	memset(&proxy, 0, addr_sz);
	proxy.sin6_family = AF_INET6;
	proxy.sin6_port = htons(4244);
	inet_pton(AF_INET6, "::1", &proxy.sin6_addr);

	/*
	 * Initialize the LCP-framework.
	 */
	port = (rand() % 9090 ) + 3000;
	if(!(ctx = lcp_init(port, 0, 0, &disco, &proxy))) {
		printf("Failed to initialize lcp-context\n");
		return -1;
	}

	printf("Internal address: %s\n", lcp_str_addr(AF_INET6, &ctx->int_addr));
	printf("External address: %s\n", lcp_str_addr(AF_INET6, &ctx->ext_addr));
	printf("Flags: "BINARY_PATTERN"\n", BINARY(ctx->net_flg));

	lcp_sock_print(&ctx->sock);

	/* Connect to the server */
	if(lcp_connect(ctx, -1, &main, LCP_CON_F_DIRECT) < 0)
		goto err_close_lcp;

	lcp_con_print(ctx);

	while(running) {
		lcp_update(ctx);

		while(lcp_pull_evt(ctx, &evt)) {
			switch(evt.type) {
				case LCP_CONNECTED:
					printf("Connected to %s:%d using slot %d\n",
							lcp_str_addr(AF_INET6, &evt.addr.sin6_addr),
							ntohs(evt.addr.sin6_port), evt.slot);
					
					if(memcmp(&main, &evt.addr, sizeof(struct sockaddr_in6)) == 0) {
						short tmp;

						lcp_sock_get_open(&ctx->sock, &tmp, 1);

						printf("Connected to the server\n");

						open_port = htons(ctx->sock.int_port[tmp]);

						buf[0] = 0x43;
						memcpy(buf + 1, &ctx->ext_addr, 16);
						memcpy(buf + 17, &open_port, 2);
						buf[19] = ctx->con_flg;

						printf("Register on server\n");
						lcp_send(ctx, &evt.addr, buf, 20);
					}
					
					else if(memcmp(&peer, &evt.addr, sizeof(struct sockaddr_in6)) == 0) {
						char buf[14];
						int tmp;
						buf[0] = 0x45;
						for(tmp = 1; tmp < 13; tmp++)
							buf[tmp] = rand() % 26 + 65;
						buf[13] = 0;

						printf("Connected to peer\n");

						printf("Send message to peer: %s\n", buf + 1);
						lcp_send(ctx, &evt.addr, buf, 14);

					}
					break;

				case LCP_DISCONNECTED:
					printf("Disconnected from %s:%d on slot %d\n",
							lcp_str_addr(AF_INET6, &evt.addr.sin6_addr),
							ntohs(evt.addr.sin6_port), evt.slot);

					if(memcmp(&peer, &evt.addr, sizeof(struct sockaddr_in6)) == 0) {
						printf("Disconnected from peer\n");

						printf("Disconnect from server\n");
						lcp_disconnect(ctx, &main);
					}
					else if(memcmp(&main, &evt.addr, sizeof(struct sockaddr_in6)) == 0) {
						printf("Disconnected from server\n");
						running = 0;
					}
					break;

				case LCP_RECEIVED:
					if(evt.buf[0] == 0x44) {
						memset(&peer, 0, addr_sz);
						peer.sin6_family = AF_INET6;
						memcpy(&peer.sin6_addr, evt.buf + 1, 16);
						memcpy(&peer.sin6_port, evt.buf + 17, 2);
						memcpy(&flg, evt.buf + 19, 1);
						memcpy(&proxy_id, evt.buf + 20, 2);

						printf("Connect to peer %s:%d using port %d\n",
							lcp_str_addr(AF_INET6, &peer.sin6_addr),
							ntohs(peer.sin6_port), ntohs(open_port));

						printf("Flags: "BINARY_PATTERN"\n", BINARY(flg));

						con = lcp_connect(ctx, ntohs(open_port), &peer, flg);
						con->proxy_id = proxy_id;
					}
					else if(evt.buf[0] == 0x45) {
						printf("Received buffer: %s\n", evt.buf + 1);

						printf("Send hint\n");
						con->pck_flg = 0;
						lcp_hint(con);

					}
					else if(evt.buf[0] == 0x46) {
						printf("Received buffer: %s\n", evt.buf + 1);

						printf("Disconnect from peer\n");
						lcp_disconnect(ctx, &evt.addr);
					}
					break;

				case LCP_HINT:
					printf("Recv Hint\n");	

					if(evt.buf[1] != 1)
						break;
					{
						char buf[14];
						int tmp;
						buf[0] = 0x46;
						for(tmp = 1; tmp < 13; tmp++)
							buf[tmp] = rand() % 26 + 65;
						buf[13] = 0;

						printf("Send message to peer: %s\n", buf + 1);
						lcp_send(ctx, &evt.addr, buf, 14);
					}
					break;

				case LCP_TIMEDOUT:
					printf("Peer timed out\n");
					running = 0;
					break;
			}

			/* Free the event */
			lcp_del_evt(&evt);
		}

		usleep(20);
	}

err_close_lcp:
	/*
	 * Shutdown the LCP-framework.
	 */
	lcp_close(ctx);
	return 0;
}
