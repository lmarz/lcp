#include "socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

LCP_API int lcp_sock_init(struct lcp_sock_tbl *tbl, char flg, 
		struct lcp_upnp_hdl *upnp, short base, short num)
{
	short i;
	short port;
	int sockfd;
	struct sockaddr_in6 addr;
	struct sockaddr *addr_ptr = (struct sockaddr *)&addr;
	int addr_sz = sizeof(addr);


	base = (base <= 0) ? LCP_SOCK_MIN_PORT : base;
	num = (num <= 0 || num > LCP_SOCK_NUM) ? LCP_SOCK_NUM : num;

	tbl->base = base;
	tbl->num = num;

	/* Setup all sockets */
	for(i = 0; i < num; i++) {
		port = base + i;

		if((sockfd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0)
			goto err_close_socks;

		tbl->mask[i] = LCP_SOCK_M_INIT;
		tbl->fd[i] = sockfd;
		tbl->con_c[i] = 0;
		tbl->int_port[i] = port;
		tbl->ext_port[i] = port;
		tbl->tout[i] = 0;
		tbl->status[i] = 0;

		memset(&addr, 0, addr_sz);
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(port);
		addr.sin6_addr = in6addr_any;

		/* Bind the socket to the port  */
		if(bind(sockfd, addr_ptr, addr_sz) < 0)
			goto err_close_socks;

		/* Set socket non-blocking */
		if(fcntl(sockfd, F_SETFL, O_NONBLOCK)  < 0)
			goto err_close_socks;

		/* Create a new uPnP entry on the NAT if possible */
		if((flg & LCP_F_UPNP) != 0 ) {
			if(lcp_upnp_add(upnp, port, port) != 0)
				goto err_close_socks;
		}

		tbl->pfds[i].fd = sockfd;
		tbl->pfds[i].events = POLLIN;
	}

	return 0;

err_close_socks:
	/* Close all opened sockets */
	for(; i >= 0; i--) {
		if((flg & LCP_F_UPNP) != 0)
			lcp_upnp_remv(upnp, tbl->ext_port[i]);

		close(tbl->fd[i]);

		/* Reset the mask of the entry */
		tbl->mask[i] = 0;
	}

	return -1;
}


LCP_API void lcp_sock_close(struct lcp_sock_tbl *tbl, char flg,
		struct lcp_upnp_hdl *upnp)
{
	int i;

	for(i = 0; i < LCP_SOCK_NUM; i++) {
		if((flg & LCP_F_UPNP) != 0)
			lcp_upnp_remv(upnp, tbl->ext_port[i]);

		close(tbl->fd[i]);

		/* Reset the mask of the entry */
		tbl->mask[i] = 0;
	}

}


LCP_API void lcp_sock_update(struct lcp_sock_tbl *tbl, char flg,
		struct lcp_upnp_hdl *upnp)
{
	time_t ti;
	int i;
	char buf[512];
	struct sockaddr *addr;
	int sz = sizeof(struct sockaddr_in6);

	time(&ti);

	for(i = 0; i < LCP_SOCK_NUM; i++) {
		if(tbl->mask[i] == 0)
			continue;

		addr = (struct sockaddr *)&tbl->dst[i];

		/* When port preservation is used */
		if((flg & LCP_F_PPR) != LCP_F_PPR) {
			/* Send a keepalive-message */
			if(ti >= tbl->tout[i]) {
				buf[0] = 0;
				buf[1] = 0;

				sendto(tbl->fd[i], buf, 2, 0, addr, sz);
				tbl->tout[i] = ti + LCP_SOCK_PPR_TOUT; 
			}
		}
	}
}


LCP_API short lcp_sel_port(struct lcp_sock_tbl *tbl, short port)
{
	int i;

	for(i = 0; i < LCP_SOCK_NUM; i++) {
		if(tbl->int_port[i] == port)
			return i;
	}

	return -1;
}


LCP_API int lcp_sock_get_open(struct lcp_sock_tbl *tbl, char flg, short *ptr,
		short num)
{
	int i;
	int c = 0;

	if(num <= 0)
		return 0;

	for(i = 0; i < LCP_SOCK_NUM; i++) {
		if(tbl->mask[i] == 0)
			continue;

		/* If a socket is open, it can be used multiple times */
		if((flg & LCP_F_OPEN) == LCP_F_OPEN) {
			ptr[c] = i;
			c++;

		}
		/* If uPnP is used, the socket can only be used once */
		else if((flg & LCP_F_UPNP) == LCP_F_UPNP) {
			if(tbl->con_c[i] == 0) {
				ptr[c] = i;
				c++;
			}
		}

		if(c >= num)
			break;
	}

	return c;
}


LCP_API int lcp_recv(struct lcp_sock_tbl *tbl, char *buf, int max_len,
		int *len, struct sockaddr_in6 *addr, short *slot)
{
	int i;
	int r;
	unsigned int size = sizeof(struct sockaddr_in6);

	if(poll(tbl->pfds, LCP_SOCK_NUM, 0) < 0)
		return 0;

	for(i = 0; i < LCP_SOCK_NUM; i++) {
		if(tbl->pfds[i].revents != 0) {
			if(tbl->pfds[i].revents & POLLIN) {
				r = recvfrom(tbl->fd[i], buf, max_len, 0, 
						(struct sockaddr *)addr, 
						&size);

				if(r > 1) {
					*len = r;
					*slot = i;
					return 1;
				}
			}
		}
	}

	return 0;
}


/* TODO: Check slot */
LCP_API int lcp_sock_send(struct lcp_sock_tbl *tbl, short slot, 
		struct sockaddr_in6 *dst, char *buf, int len)
{
	int tmp = sizeof(struct sockaddr_in6);
	return sendto(tbl->fd[slot], buf, len, 0, (struct sockaddr *)dst, tmp);
}


LCP_API void lcp_print_sock(struct lcp_sock_tbl *tbl)
{
	int i;

	printf("   \tMASK\tFD\tINT_PORT\tEXT_PORT\tTOUT\n");
	for(i = 0; i < LCP_SOCK_NUM; i++) {
		printf("[%02x]\t%d\t%d\t%d   \t%d   \t%lu\n", i,
				tbl->mask[i], tbl->fd[i], 
				tbl->int_port[i], tbl->ext_port[i], 
				tbl->tout[i]);
	}
	printf("\n");
}
