#include "socket.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "error.h"
#include "upnp.h"

LCP_API int lcp_sock_init(struct lcp_sock_tbl *tbl, char flg, 
		void *hdl, short base, short num)
{
	short i;
	short port;
	int sockfd;
	struct sockaddr_in6 addr;
	struct sockaddr *addr_ptr = (struct sockaddr *)&addr;
#ifdef __MINGW32__
	u_long nonblock = 1;
#endif /* __MINGW32__ */

	base = (base <= 0) ? LCP_SOCK_MIN_PORT : base;
	num = (num <= 0 || num > LCP_SOCK_NUM) ? LCP_SOCK_NUM : num;

	tbl->base = base;
	tbl->num = num;
	tbl->flg = flg;
	tbl->hdl = hdl;

	/* Setup all sockets */
	for(i = 0; i < num; i++) {
		port = base + i;

		/* Create socket */
		if((sockfd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0)
			goto err_close_socks;

		tbl->mask[i] = LCP_SOCK_M_INIT;
		tbl->fd[i] = sockfd;
		tbl->con_c[i] = 0;
		tbl->int_port[i] = htons(port);
		tbl->ext_port[i] = htons(port);
		tbl->tout[i] = 0;
		tbl->status[i] = 0;

		memset(&addr, 0, ADDR6_SIZE);
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(port);
		addr.sin6_addr = in6addr_any;

		/* Bind the socket to the port  */
		if(bind(sockfd, addr_ptr, ADDR6_SIZE) < 0)
			goto err_close_socks;

		/* Set socket non-blocking */
#ifndef __MINGW32__
		if(fcntl(sockfd, F_SETFL, O_NONBLOCK)  < 0)
			goto err_close_socks;
#else
		if(ioctlsocket(sockfd, FIONBIO, &nonblock) != NO_ERROR)
			goto err_close_socks;
#endif /* __MINGW32__ */

		/* Forward ports on the NAT using uPnP entry if possible */
		if((flg & LCP_NET_F_UPNP) != 0 ) {
			if(lcp_upnp_add(hdl, port, port) != 0) {
				lcp_errno = LCP_ESOUPNP;
				goto err_close_socks;
			}
		}

		tbl->pfds[i].fd = sockfd;
		tbl->pfds[i].events = POLLIN;
	}
	return 0;

err_close_socks:
	/* Close all opened sockets */
	for(; i >= 0; i--) {
		if((flg & LCP_NET_F_UPNP) != 0)
			lcp_upnp_remv(hdl, tbl->ext_port[i]);

		close(tbl->fd[i]);

		/* Reset the mask of the entry */
		tbl->mask[i] = 0;
	}

	return -1;
}


LCP_API void lcp_sock_close(struct lcp_sock_tbl *tbl)
{
	int i;

	for(i = 0; i < tbl->num; i++) {
		if(tbl->mask[i] == 0)
			continue;

		if((tbl->flg & LCP_NET_F_UPNP) != 0)
			lcp_upnp_remv(tbl->hdl, tbl->ext_port[i]);

		close(tbl->fd[i]);

		/* Reset the mask of the entry */
		tbl->mask[i] = 0;
	}

}


LCP_API short lcp_sock_sel_port(struct lcp_sock_tbl *tbl, short port)
{
	int i;

	for(i = 0; i < tbl->num; i++) {
		if(tbl->int_port[i] == port)
			return i;
	}

	return -1;
}


LCP_API int lcp_sock_get_open(struct lcp_sock_tbl *tbl, short *ptr, short num)
{
	int i;
	int c = 0;

	if(num <= 0)
		return 0;

	for(i = 0; i < tbl->num; i++) {
		if(tbl->mask[i] == 0)
			continue;

		/* If a socket is open, it can be used multiple times */
		if((tbl->flg & LCP_NET_F_OPEN) == LCP_NET_F_OPEN) {
			ptr[c] = i;
			c++;

		}
		else if(tbl->con_c[i] == 0) {
			ptr[c] = i;
			c++;
		}

		if(c >= num)
			break;
	}

	return c;
}


LCP_API int lcp_sock_recv(struct lcp_sock_tbl *tbl, char *buf, int max_len,
		int *len, struct sockaddr_in6 *addr, short *slot)
{
	int i;
	int r;
#ifndef __MINGW32__
	unsigned int size = ADDR6_SIZE;
#else
	int size = ADDR6_SIZE;
#endif /* __MINGW32__ */

#ifndef __MINGW32__
	if(poll(tbl->pfds, tbl->num, 0) < 0)
		return 0;
#else
	if(WSAPoll(tbl->pfds, tbl->num, 0) < 0)
		return 0;
#endif /* __MINGW32__ */

	for(i = 0; i < tbl->num; i++) {
		if(tbl->pfds[i].revents != 0) {
			if(tbl->pfds[i].revents & POLLIN) {
				r = recvfrom(tbl->fd[i], buf, max_len, 0, 
						(struct sockaddr *)addr, 
						&size);

				if(r >= 1) {
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
	int tmp = ADDR6_SIZE;
	return sendto(tbl->fd[slot], buf, len, 0, (struct sockaddr *)dst, tmp);
}


LCP_API void lcp_sock_print(struct lcp_sock_tbl *tbl)
{
	int i;

	printf("\n___________________  SOCKET-TABLE  ____________________\n");

	printf("     MASK   FD   CNT   INT_PORT   EXT_PORT         TOUT\n");
	for(i = 0; i < LCP_SOCK_NUM; i++) {
		printf("%02x:  %4d   %2d   %3d   %8d   %8d   %10lu\n", i,
				tbl->mask[i], tbl->fd[i], tbl->con_c[i],
				ntohs(tbl->int_port[i]), 
				ntohs(tbl->ext_port[i]), tbl->tout[i]);
	}
	printf("\n");
}
