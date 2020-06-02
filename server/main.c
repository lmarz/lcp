#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include "../inc/lcp.h"

#define PORT 25252

struct peer {
	struct sockaddr_in6 real;
	struct sockaddr_in6 alias;
	char flg;
	short slot;
};

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
	int s, i;
	int port;
	int peer_c = 0;
	struct peer peers[2];

	struct lcp_evt evt;

	srand(time(NULL));

	/*
	 * Initialize the LCP-framework.
	 */
	if(!(ctx = lcp_init(PORT, 0, LCP_F_OPEN, NULL, NULL))) {
		printf("Failed to initialize lcp-context\n");
		return -1;
	}

	while(running) {
		lcp_update(ctx);

		while(lcp_pull_evt(ctx, &evt)) {
			switch(evt.type) {
				case 0x01:
					printf("Connected to %s:%d on port %d\n",
							lcp_str_addr(AF_INET6, 
								&evt.addr.sin6_addr),
							evt.addr.sin6_port, 
							evt.slot);
					break;

				case 0x02:
					printf("Disconnected from %s:%d on port %d\n",
							lcp_str_addr(AF_INET6, &evt.addr.sin6_addr),
							evt.addr.sin6_port, evt.slot);
					break;

				case 0x03:
					printf("New request 0x%02x\n", (char)evt.buf[0]);

					if(evt.buf[0] == 0x43) {
						memcpy(&peers[peer_c].real, &evt.addr, sizeof(struct sockaddr_in6));
					
						memset(&peers[peer_c].alias, 0, sizeof(struct sockaddr_in6));
						peers[peer_c].alias.sin6_family = AF_INET6;
						peers[peer_c].alias.sin6_port = *(short *)(evt.buf + 17);
						memcpy(&peers[peer_c].alias.sin6_addr, evt.buf + 1, 16);
					
						printf("New Peer %s:%d\n",
							lcp_str_addr(AF_INET6, &peers[peer_c].alias.sin6_addr),
							ntohs(peers[peer_c].alias.sin6_port));

						memcpy(&peers[peer_c].flg, buf + 3, 1);
						peers[peer_c].slot = evt.slot;
						peer_c++;

						if(peer_c >= 2) {
							for(i = 0; i < 2; i++) {
								memset(buf, 0, 20);
								buf[0] = 0x44;
								memcpy(buf + 1, &peers[(i + 1) % 2].alias.sin6_addr, 16);
								memcpy(buf + 17, &peers[(i + 1) % 2].alias.sin6_port, 2);
								memcpy(buf + 19, &peers[(i + 1) % 2].flg, 1);
								lcp_send(ctx, &peers[i].real, buf, 20);
							}
						}
					}
					break;
			}

			/* Free the event */
			lcp_del_evt(&evt);
		}

		usleep(50);
	}

err_close_lcp:
	/*
	 * Shutdown the LCP-framework.
	 */
	lcp_close(ctx);
	return 0;
}
