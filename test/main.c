#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include "../inc/lcp.h"

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


static int kbhit(void);


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

	struct sockaddr_in6 disco;
	struct sockaddr_in6 proxy;

	struct lcp_evt evt;

	srand(time(NULL));

	memset(&disco, 0, addr_sz);
	disco.sin6_family = AF_INET6;
	disco.sin6_port = htons(4243);
	inet_pton(AF_INET6, "0:0:0:0:0:ffff:4e2f:27b2", &disco.sin6_addr);

	memset(&proxy, 0, addr_sz);
	proxy.sin6_family = AF_INET6;
	proxy.sin6_port = htons(4244);
	inet_pton(AF_INET6, "0:0:0:0:0:ffff:4e2f:27b2", &proxy.sin6_addr);

	port = (rand() % 9090 ) + 3000;
	if(!(ctx = lcp_init(port, 0, &disco, &proxy))) {
		printf("Failed to initialize lcp-context\n");
		return -1;
	}

	printf("Internal address: %s\n", lcp_str_addr(AF_INET6, &ctx->int_addr));
	printf("External address: %s\n", lcp_str_addr(AF_INET6, &ctx->ext_addr));
	printf("Flags: "BINARY_PATTERN"\n", BINARY(ctx->flg));

	while(running) {
		lcp_update(ctx);

		if(kbhit()) {
			char c = getchar();
			int type;
			switch(c) {
				case 0x63:    /* Press C to start connection */
					printf("Connect\n");
					
					printf("Addr: ");
					scanf("%s", buf);
					printf("Port: ");
					scanf("%d", &port);

					printf("Type (0: P2P, 2: PROXY): ");
					scanf("%d", &type);

					memset(&addr, 0, addr_sz);
					addr.sin6_family = AF_INET6;
					addr.sin6_port = htons(port);
					inet_pton(AF_INET6, buf, &addr.sin6_addr);

					lcp_connect(ctx, -1, &addr, (uint8_t)type);
					break;

				case 0x76:    /* Press V to close connection */
					printf("Disconnect\n");
					
					printf("Addr: ");
					scanf("%s", buf);
					printf("Port: ");
					scanf("%d", &port);

					memset(&addr, 0, addr_sz);
					addr.sin6_family = AF_INET6;
					addr.sin6_port = htons(port);
					inet_pton(AF_INET6, buf, &addr.sin6_addr);

					lcp_disconnect(ctx, &addr);
					break;
				
				case 0x64:    /* Press D to show socket-table */
					lcp_print_sock(&ctx->sock);
					break;

				case 0x66:    /* Press F to show connection-list  */
					lcp_con_print(ctx);
					break;

				case 0x71:    /* Press Q to quit */
					running = 0;
					break;

				case 0x6d:    /* Press M to send message */
					printf("Send message\n");
					
					printf("Addr: ");
					scanf("%s", buf);
					printf("Port: ");
					scanf("%d", &port);

					memset(&addr, 0, addr_sz);
					addr.sin6_family = AF_INET6;
					addr.sin6_port = htons(port);
					inet_pton(AF_INET6, buf, &addr.sin6_addr);

					printf("Message: ");
					scanf("%s", buf);

					lcp_send(ctx, &addr, buf, strlen(buf) + 1);
					break;
			}
		}

		while(lcp_pull_evt(ctx, &evt)) {
			switch(evt.type) {
				case 0x01:
					printf("Connected to %s:%d on port %d\n",
							lcp_str_addr(AF_INET6, &evt.addr.sin6_addr),
							evt.addr.sin6_port, evt.slot);
					break;

				case 0x02:
					printf("Disconnected from %s:%d on port %d\n",
							lcp_str_addr(AF_INET6, &evt.addr.sin6_addr),
							evt.addr.sin6_port, evt.slot);
					break;

				case(0x03):
					printf("Received %d bytes: %s\n", evt.len, evt.buf);
					break;
			}

			/* Free the event */
			lcp_del_evt(&evt);
		}

		sleep(1);
	}

	lcp_close(ctx);
	return 0;
}


static int kbhit(void)
{
	struct termios oldt, newt;
	int ch;
	int oldf;

	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
	fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);

	ch = getchar();

	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	fcntl(STDIN_FILENO, F_SETFL, oldf);

	if(ch != EOF) {
		ungetc(ch, stdin);
		return 1;
	}

	return 0;
}

