#include "lcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ifaddrs.h>

/* Initialize the default server-addresses for the DISCO- and PROXY-server */
LCP_INTERN int lcp_init_addr(struct lcp_ctx *ctx)
{
	memset(&ctx->disco_addr, 0, ADDR6_SIZE);
	ctx->disco_addr.sin6_family = AF_INET6;
	ctx->disco_addr.sin6_port = htons(LCP_DISCO_PORT);
	if(inet_pton(AF_INET6, LCP_DISCO_IP, &ctx->disco_addr.sin6_addr) < 0)
		return -1;

	memset(&ctx->proxy_addr, 0, ADDR6_SIZE);
	ctx->proxy_addr.sin6_family = AF_INET6;
	ctx->proxy_addr.sin6_port = htons(LCP_PROXY_PORT);
	if(inet_pton(AF_INET6, LCP_PROXY_IP, &ctx->proxy_addr.sin6_addr) < 0)
		return -1;

	return 0;
}


/* Get the external address and check if port preservation is enabled */
LCP_INTERN int lcp_discover(struct lcp_ctx *ctx)
{
	int sockfd;
	int port;
	struct sockaddr_in6 cli;
	struct sockaddr *cli_ptr = (struct sockaddr *)&cli;
	struct sockaddr *serv_ptr;
	struct sockaddr_in6 res;
	struct timeval tv;
	int tv_sz = sizeof(struct timeval);

	if((sockfd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0)
		return -1;

	/* Set timeout for receiving data */
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, tv_sz) < 0)
		goto err_close_sockfd;

	/* Choose a random port */
	port = 27000 + (rand() % 2525);

	/* Bind the socket to the port */
	memset(&cli, 0, ADDR6_SIZE);
	cli.sin6_family = AF_INET6;
	cli.sin6_port = htons(port);
	cli.sin6_addr = in6addr_any;
	if(bind(sockfd, cli_ptr, ADDR6_SIZE) < 0)
		goto err_close_sockfd;

	serv_ptr = (struct sockaddr *)&ctx->disco_addr;

	/* Send a request to the disco-server */
	if(sendto(sockfd, "bazinga\0", 8, 0, serv_ptr, ADDR6_SIZE) < 0)
		goto err_close_sockfd;

	/* Listen for a response from the server */
	if(recvfrom(sockfd, &res, ADDR6_SIZE, 0, NULL, NULL) < 0)
		goto err_close_sockfd;

	/* Copy the external IPv6-address and port */
	ctx->ext_addr = res.sin6_addr;

	/* Check if port-preservation is enabled */
	if(ntohs(res.sin6_port) == port)
		ctx->net_flg = ctx->net_flg | LCP_NET_F_PPR;

	/* Check if uPnP is enabled */
	if(lcp_upnp_prep(&ctx->upnp) == 0)
		ctx->net_flg = ctx->net_flg | LCP_NET_F_UPNP;

	/* Use proxy by default */
	ctx->con_flg = LCP_CON_F_PROXY;

	/* Check if direct connection are possible */
	if(ctx->net_flg > 0)
		ctx->con_flg = LCP_CON_F_DIRECT;

	close(sockfd);
	return 0;

err_close_sockfd:
	close(sockfd);
	return -1;
}


/* Get the internal IPv6-address */
LCP_INTERN int lcp_get_intern(struct lcp_ctx *ctx)
{
	struct ifaddrs *addrs;
	struct ifaddrs *tmp;
	struct sockaddr_in *paddr;
	int ret = -1;

	getifaddrs(&addrs);
	tmp = addrs;

	while(tmp) {
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) {
			paddr = (struct sockaddr_in *)tmp->ifa_addr;
			if(*(int *)&paddr->sin_addr != 0x0100007F) {
				lcp_btob_4to6(&paddr->sin_addr, &ctx->int_addr);
				ret = 0;
				break;
			}
		}

		tmp = tmp->ifa_next;
	}

	freeifaddrs(addrs);
	return ret;
}


LCP_API struct lcp_ctx *lcp_init(short base, short num, char ovw, 
		struct sockaddr_in6 *disco, struct sockaddr_in6 *proxy)
{
	struct lcp_ctx *ctx;

	if(!(ctx = malloc(sizeof(struct lcp_ctx))))
		return NULL;

	if(ovw) {
		/* Set initial values of variables of the context */
		ctx->net_flg = ovw;
		ctx->con_flg = 0;
		ctx->evt = NULL;

		/* Set the initial values of the connection-list */
		ctx->con.tbl = NULL;
		ctx->con.num = 0;
	}
	else {
		/* Set initial values of variables of the context */
		ctx->net_flg = 0;
		ctx->evt = NULL;

		/* Set the initial values of the connection-list */
		ctx->con.tbl = NULL;
		ctx->con.num = 0;

		/* Initialize the default server-addresses */
		if(lcp_init_addr(ctx) < 0)
			goto err_free_ctx;

		if(disco != NULL)
			ctx->disco_addr = *disco;
		if(proxy != NULL)
			ctx->proxy_addr = *proxy;

		/* Discover the external address and test port preservation */
		if(lcp_discover(ctx) < 0) {
			lcp_errno = LCP_EDISCO;
			goto err_free_ctx;
		}

		/* Discover the internal address */
		if(lcp_get_intern(ctx) < 0) {
			lcp_errno = LCP_EINTERN;
			goto err_free_ctx;
		}
	}

	/* Initialize the socket-table */
	if(lcp_sock_init(&ctx->sock, ctx->net_flg, &ctx->upnp, base, num) < 0) {
		lcp_errno = LCP_ESOCKINI;
		goto err_free_ctx;
	}

	/* Initialize key-buffers */
	lcp_init_pvt(&ctx->pvt);
	lcp_init_pub(&ctx->pub);

	/* Initialize the keys */
	lcp_gen_keys(&ctx->pvt, &ctx->pub);
	return ctx;

err_free_ctx:
	free(ctx);
	return NULL;
}


LCP_API void lcp_close(struct lcp_ctx *ctx)
{
	if(!ctx)
		return;

	/* Clear key-buffers */
	lcp_clear_pvt(&ctx->pvt);
	lcp_clear_pub(&ctx->pub);

	/* Clear the connection-list */
	lcp_con_close(ctx);

	/* Close all sockets and clear the socket-table */
	lcp_sock_close(&ctx->sock);

	/* Cleanup uPnP if necessary */
	if((ctx->net_flg & LCP_NET_F_UPNP) == LCP_NET_F_UPNP)
		lcp_upnp_close(&ctx->upnp);

	/* Free the context-struct */
	free(ctx);
}


LCP_API short lcp_get_slot(struct lcp_ctx *ctx)
{
	short idx;

	if(lcp_sock_get_open(&ctx->sock, &idx, 1) == 0)
		return -1;

	return idx;
}


LCP_API struct lcp_con *lcp_connect(struct lcp_ctx *ctx, short port, 
		struct sockaddr_in6 *addr, char con_flg, uint8_t pck_flg)
{
	short slot;
	int tmp;
	struct lcp_sock_tbl *tbl = &ctx->sock;
	struct lcp_con *con;

	/* Check if there already is a connection */
	if((con = lcp_con_sel_addr(ctx, addr)))
		return con;

	if(port >= 0) {
		if((slot = lcp_sock_sel_port(tbl, port)) < 0)
			return NULL;

		if(tbl->mask[slot] == 0)
			return NULL;

		if((ctx->net_flg & LCP_NET_F_UPNP) == LCP_NET_F_UPNP && 
				tbl->con_c[slot] > 0)
			return NULL;
	}
	else {
		if((tmp = lcp_sock_get_open(tbl, &slot, 1)) < 1)
			return NULL;
	}

	/* Add a new connection to the connection-table */
	if(!(con = lcp_con_add(ctx, slot, addr, con_flg, pck_flg)))
		return NULL;

	/* Require connection send JOI */
	con->status = 0x01;

	/* If a direct connection should be extablished, skip proxy */
	if((con_flg & LCP_CON_F_DIRECT) == LCP_CON_F_DIRECT)
		con->status = 0x04;

	/* Send a single packet to the destination */
	tmp = 0;
	lcp_con_send(ctx, con, (char *)&tmp, 2);
	return con;
}


LCP_API int lcp_disconnect(struct lcp_ctx *ctx, struct sockaddr_in6 *addr)
{
	struct lcp_con *ptr;

	if(!(ptr = lcp_con_sel_addr(ctx, addr)))
		return -1;

	if(ptr->status != 0x07)
		return -1;

	/* Require connection to send FIN */
	ptr->status = 0x08;
	ptr->tout = 0;
	ptr->count = 0;
	return 0;
}


LCP_API void lcp_update(struct lcp_ctx *ctx)
{
	/* Update the connection-list */
	lcp_con_update(ctx);
}


LCP_API int lcp_send(struct lcp_ctx *ctx, struct sockaddr_in6 *addr, 
		char *buf, int len)
{
	char *cont_buf;
	int cont_len;
	char *pck_buf;
	int pck_len;
	struct lcp_hdr hdr;
	uint16_t id;
	struct lcp_con *con;

	/* Get the id of the packet */
	/* TODO: Replace with better id-number */
	id = rand() % 0xffff;

	/* Get the connection */
	if(!(con = lcp_con_sel_addr(ctx, addr)))
		return -1;

	/* If encryption should be used */
	if((con->pck_flg & LCP_F_ENC) == LCP_F_ENC) {
		lcp_encrypt(&cont_buf, &cont_len, buf, len, con->pub);
	}
	else {
		cont_buf = buf;
		cont_len = len;
	}

	/* Allocate memory for the packet */
	pck_len = cont_len + LCP_HDR_SIZE;
	if(!(pck_buf = malloc(pck_len)))
		return -1;

	/* Set the packet-header */
	hdr.id = id;
	hdr.cb = LCP_C_PSH;
	hdr.flg = con->pck_flg;

	/* Copy everything into the packet-buffer */
	memcpy(pck_buf, &hdr, LCP_HDR_SIZE);
	memcpy(pck_buf + LCP_HDR_SIZE, cont_buf, cont_len);

	if((con->pck_flg & LCP_F_ENC) == LCP_F_ENC)
		free(cont_buf);

	/* Add packet to the packet-queue */
	if(lcp_que_add(con, pck_buf, pck_len, id) < 0)
		goto err_free_pck_buf;

	free(pck_buf);
	return 0;

err_free_pck_buf:
	free(pck_buf);
	return -1;
}


LCP_API int lcp_sendto(struct lcp_ctx *ctx, struct sockaddr_in6 *addr,
		uint8_t op, char *buf, int len)
{
	char *pck_buf;
	int pck_len;
	struct lcp_hdr hdr;
	uint16_t id;
	struct lcp_con *con;

	/* Get the id of the packet */
	/* TODO: Replace with better id-number */
	id = rand() % 0xffff;

	/* Get the connection */
	if(!(con = lcp_con_sel_addr(ctx, addr)))
		return -1;

	/* The length can't be smaller than 0 */
	len = len < 0 ? 0 : len;

	/* Allocate memory for the packet */
	pck_len = len + LCP_HDR_SIZE;
	if(!(pck_buf = malloc(pck_len)))
		return -1;

	/* Set the packet-header */
	hdr.id = id;
	hdr.cb = op;
	hdr.flg = con->pck_flg;

	/* Copy everything into the packet-buffer */
	memcpy(pck_buf, &hdr, LCP_HDR_SIZE);

	/* Copy the buffer into the packet if necessary */
	if(len > 0)
		memcpy(pck_buf + LCP_HDR_SIZE, buf, len);

	/* Add packet to the packet-queue */
	if(lcp_que_add(con, pck_buf, pck_len, id) < 0)
		goto err_free_pck_buf;

	free(pck_buf);
	return 0;

err_free_pck_buf:
	free(pck_buf);
	return -1;

}


LCP_API void lcp_con_close(struct lcp_ctx *ctx)
{
	struct lcp_con *ptr;
	struct lcp_con *next;

	ptr = ctx->con.tbl;
	while(ptr != NULL) {
		next = ptr->next;

		lcp_clear_pub(&ptr->pub);
		free(ptr);

		ptr = next;
	}
}


LCP_API int lcp_hint(struct lcp_con *con, uint8_t pck_flg)
{
	if(con->status != 0x07)
		return -1;

	/* Can't enable encryption if keys have not been exchanged */
	if((pck_flg & LCP_F_ENC) != 0 && (con->ini_pck_flg & LCP_F_ENC) == 0)
		return -1;

	/* If the new flags are the same as the old ones */
	if(con->pck_flg == pck_flg)
		return 0;

	/* Set packet-flags of connection */
	con->pck_flg = pck_flg;

	/* Update status of connection */
	con->status = 0x0d;
	con->tout = 0;
	con->count = 0;
	return 0;
}


LCP_API struct lcp_con *lcp_con_add(struct lcp_ctx *ctx, short slot,
		struct sockaddr_in6 *addr, char con_flg, uint8_t pck_flg)
{
	struct lcp_con_lst *tbl = &ctx->con;
	struct lcp_con *con;
	struct lcp_con *ptr;
	time_t ti;

	time(&ti);

	/* Allocate memory for the new entry */
	if(!(con = malloc(sizeof(struct lcp_con))))
		return NULL;

	con->next = NULL;
	con->addr = *addr;
	con->slot = slot; 

	con->con_flg = con_flg;
	con->ini_pck_flg = pck_flg;
	con->pck_flg = pck_flg;
	con->que = NULL;

	con->count = 0;
	con->tout = 0;

	con->proxy_id = 0;

	/* Setup public key */
	lcp_init_pub(&con->pub);

	/* Update the socket */
	if((ctx->net_flg & LCP_NET_F_PPR) == LCP_NET_F_PPR) {
		if((con_flg & LCP_CON_F_DIRECT) != LCP_CON_F_DIRECT)
			ctx->sock.dst[slot] = ctx->proxy_addr;
		else
			ctx->sock.dst[slot] = *addr;

		ctx->sock.tout[slot] = ti;
	}

	/* Increment the number of connections using socket */
	ctx->sock.con_c[slot]++;

	if(tbl->tbl == NULL) {
		tbl->tbl = con;
		tbl->num = 1;
	}
	else {
		ptr = tbl->tbl;
		while(ptr->next != NULL)
			ptr = ptr->next;

		ptr->next = con;
		tbl->num++;
	}

	return con;
}


LCP_API void lcp_con_remv(struct lcp_ctx *ctx, struct sockaddr_in6 *addr)
{
	struct lcp_con *prev;
	struct lcp_con *ptr;
	struct lcp_pck_que *que_ptr;
	struct lcp_pck_que *que_next;

	prev = NULL;
	ptr = ctx->con.tbl;

	while(ptr != NULL) {
		if(memcmp(&ptr->addr, addr, ADDR6_SIZE) == 0) {
			/* Decrement the number of connections using socket */
			ctx->sock.con_c[ptr->slot]--;	

			if(prev == NULL)
				ctx->con.tbl = ptr->next;
			else
				prev->next = ptr->next;

			lcp_clear_pub(&ptr->pub);

			/* Clear the packet-queue */
			que_ptr = ptr->que;
			while(que_ptr != NULL) {
				que_next = que_ptr->next;

				if(que_ptr->buf != NULL)
					free(que_ptr->buf);

				free(que_ptr);

				que_ptr = que_next;
			}

			free(ptr);
			ctx->con.num--;
			return;
		}

		prev = ptr;
		ptr = ptr->next;
	}
}


LCP_INTERN int lcp_addr_comp(struct lcp_ctx *ctx, short slot, 
		struct sockaddr_in6 *addr)
{
	unsigned long a = 0, b = 0;
	unsigned short a_port, b_port;
	char *ap = (char *)&a;
	char *bp = (char *)&b;

	memset(&a, 0, 8);
	memset(&b, 0, 8);

	a_port = ctx->sock.ext_port[slot];
	b_port = addr->sin6_port;

	memcpy(ap + 2, &a_port, 2);
	memcpy(ap + 4, (char *)&ctx->ext_addr + 12, 4);

	memcpy(bp + 2, &b_port, 2);
	memcpy(bp + 4, (char *)&addr->sin6_addr + 12, 4);

	if(a > b)
		return 1;

	return 0;
}


LCP_INTERN void lcp_con_recv(struct lcp_ctx *ctx)
{
	struct lcp_con *con;
	struct lcp_con *ptr;
	struct lcp_hdr hdr;
	struct lcp_sock_tbl *sock = &ctx->sock;
	char buf[512];
	char *buf_ptr;
	int len;
	short slot;
	time_t ti;
	struct sockaddr_in6 cli;
	uint16_t proxy_id;

	time(&ti);

	while(lcp_sock_recv(sock, buf, 512, &len, &cli, &slot)) {
		buf_ptr = buf;
		buf_ptr[len] = 0;

		/* Drop packet if it'S to short */
		if(len < 4)
			continue;

		memcpy(&proxy_id, buf_ptr + 2, 2);

		/* 
		 * Handle packets from the proxy.
		 */
		if((unsigned char)buf_ptr[0] == 0xff) {
			if(!(ptr = lcp_con_sel_proxy(ctx, proxy_id)))
				continue;

			/*
			 * Successfully joined link. 
			 */
			if(buf_ptr[1] == 0x05 && ptr->status == 0x01) {
				/* Await other link to initate connection */
				ptr->status = 0x02;
				continue;
			}
			/* 
			 * Other link connected to the link, initiate new
			 * connection.
			 */
			else if(buf_ptr[1] == 0x04 && ptr->status == 0x02) {
				/* Require connection send INI */
				ptr->status = 0x04;
				continue;
			}
			/*
			 * Disconnected from proxy-link.
			 */
			else if(buf_ptr[1] == 0x05 && ptr->status == 0x0c) {
				/* Create a new event */
				lcp_push_evt(ctx, LCP_DISCONNECTED, ptr->slot,
						&ptr->addr, NULL, 0);

				/* Remove the entry from the connection-list */
				lcp_con_remv(ctx, &ptr->addr);
				continue;
			}

			/* Skip the proxy-header */
			buf_ptr += 4;
		}
		else {
			/* Get a pointer to the connection-struct */
			ptr = lcp_con_sel_addr(ctx, &cli);
		}

		/* Get header from buffer */
		memcpy(&hdr, buf_ptr, LCP_HDR_SIZE);

		/* INI */
		if((hdr.cb & LCP_C_INI) == LCP_C_INI) {
			/* INI-ACK */
			if(hdr.cb & LCP_C_ACK) {
				char n[128];
				char e[1];
				int tmp = sizeof(char);

				if(ptr == NULL || ptr->status >= 0x06)
					continue;

				/* If encryption enabled from the start */
				if((ptr->pck_flg & LCP_F_ENC) == LCP_F_ENC) {
					/* Read public-key */
					memcpy(n, buf_ptr + 4, 128);
					memcpy(e, buf_ptr + 132, 1);

					mpz_import(ptr->pub.n, 128, 1, tmp, 0, 
							0, n);
					mpz_import(ptr->pub.e, 1, 1, tmp, 0, 
							0, e);
				}

				/* Require connection to send ACK */
				ptr->status = 0x06;

#if LCP_DEBUG
				printf("Recv INI-ACK from %s (%d)\n", 
						lcp_str_addr6(&cli), len);
#endif
			}
			/* Just INI */
			else {
				char n[128];
				char e[1];
				int tmp = sizeof(char);

				if(ptr != NULL) {
					if(ptr->status > 0x04)
						continue;

					if(ptr->status == 0x04 && lcp_addr_comp(
								ctx, ptr->slot, 
								&ptr->addr))
						continue;

					con = ptr;
				}
				else {
					char con_flg = LCP_CON_F_DIRECT;

					/* Push new entry in connection-list */
					con = lcp_con_add(ctx, slot, &cli,
							con_flg, hdr.flg);

					if(con == NULL)
						continue;
				}

				/* If encryption enabled from the start */
				if((con->pck_flg & LCP_F_ENC) == LCP_F_ENC) {
					/* Read public-key */
					memcpy(n, buf_ptr + 4, 128);
					memcpy(e, buf_ptr + 132, 1);

					mpz_import(con->pub.n, 128, 1, tmp, 0,
							0, n);
					mpz_import(con->pub.e, 1, 1, tmp, 0,
							0, e);
				}

				/* Require connection to send INI-ACK */
				con->status = 0x05;
				con->tout = ti + 1;
				con->count = 0;

#if LCP_DEBUG
				printf("Recv INI from %s (%d)\n",
						lcp_str_addr6(&cli), len);
#endif
			}

			continue;	
		}
		/* FIN */
		if((hdr.cb & LCP_C_FIN) == LCP_C_FIN) {
			/* FIN-ACK */
			if(hdr.cb & LCP_C_ACK) {
				if(ptr->status >= 0x0a)
					continue;

				/* Require connection to send ACK */
				ptr->status = 0x0a;

#if LCP_DEBUG
				printf("Recv FIN-ACK from %s (%d)\n",
						lcp_str_addr6(&cli), len);
#endif
			}
			/* Just FIN */
			else {
				if(ptr == NULL || ptr->status >= 0x09)
					continue;

				if(ptr->status == 0x08 && lcp_addr_comp(ctx, 
							ptr->slot, &ptr->addr))
					continue;

				/* Require connection to send FIN-ACK */
				ptr->status = 0x09;
				ptr->tout = ti + 1;
				ptr->count = 0;

#if LCP_DEBUG
				printf("Recv FIN from %s (%d)\n",
						lcp_str_addr6(&cli), len);
#endif
			}
			continue;
		}
		/* ACK */
		if((hdr.cb & LCP_C_ACK) == LCP_C_ACK) {
			struct lcp_pck_que *pck;

			if(ptr == NULL)
				continue;

			/* Acknowledge new connection */
			if(ptr->status == 0x05) {
				/* Mark connection as established */
				ptr->status = 0x07;

				/* Create new event */
				lcp_push_evt(ctx, LCP_CONNECTED, ptr->slot, 
						&ptr->addr, NULL, 0);

#if LCP_DEBUG
				printf("Recv ACK from %s (%d)\n",
						lcp_str_addr6(&cli), len);
#endif

				continue;
			}

			/* Acknowledge closing a connection */
			if(ptr->status == 0x09) {
				if(ptr->con_flg == LCP_CON_F_PROXY) {
					ptr->status = 0x0c;
					ptr->tout = ti;
					ptr->count = 0;
					continue;
				}

				/* Create a new event */
				lcp_push_evt(ctx, LCP_DISCONNECTED, ptr->slot,
						&ptr->addr, NULL, 0);

				/* Remove the entry from the connection-list */
				lcp_con_remv(ctx, &ptr->addr);

#if LCP_DEBUG
				printf("Recv ACK from %s (%d)\n",
						lcp_str_addr6(&cli), len);
#endif

				continue;
			}
			/* Acknowledge hint */
			if(ptr->status == 0x0d) {
				char info[2];

				/* Reset status */
				ptr->status = 0x07;

				info[0] = ptr->pck_flg;
				info[1] = 0;

				/* Create a new event */
				lcp_push_evt(ctx, LCP_HINT, ptr->slot,
						&ptr->addr, info, 2);

#if LCP_DEBUG
				printf("Recv ACK from %s (%d)\n",
						lcp_str_addr6(&cli), len);
#endif

				continue;
			}

			if(!(pck = lcp_que_sel(ptr, hdr.id))) {
				/* No packet with that ID has been sent */
				continue;
			}

			/* Remove package from the package-list */
			lcp_que_remv(ptr, pck);
		}
		/* PSH */
		if((hdr.cb & LCP_C_PSH) == LCP_C_PSH) {
			char *cont_buf;
			int cont_len;

			/* Verify this is an established connection */
			if(ptr == NULL || ptr->status != 0x07)
				continue;

			if((hdr.flg & LCP_F_ENC) == LCP_F_ENC) {
				lcp_decrypt(&cont_buf, &cont_len, 
						buf_ptr + LCP_HDR_SIZE,
						len - LCP_HDR_SIZE, ctx->pvt);
			}
			else {
				cont_buf = buf_ptr + LCP_HDR_SIZE;
				cont_len = len - LCP_HDR_SIZE;
			}

			/* Create new event */
			lcp_push_evt(ctx, LCP_RECEIVED, ptr->slot, &ptr->addr, 
					cont_buf, cont_len);	

			if((hdr.flg & LCP_F_ENC) == LCP_F_ENC)
				free(cont_buf);

			/* Send an acknowledgement for the packet */
			hdr.cb = LCP_C_ACK;
			lcp_con_send(ctx, ptr, (char *)&hdr, LCP_HDR_SIZE);

#if LCP_DEBUG
			printf("Recv PSH from %s (%d)\n",
					lcp_str_addr6(&cli), len);
#endif
		}
		/* HNT */
		if((hdr.cb & LCP_C_HNT) == LCP_C_HNT) {
			char info[2];

			/* Connection not established or closing */
			if(ptr->status != 0x07)
				continue;

			/* Copy the packet-flags */
			ptr->pck_flg = hdr.flg;

			/* Send an acknowledgement for the packet */
			hdr.cb = LCP_C_ACK;
			lcp_con_send(ctx, ptr, (char *)&hdr, LCP_HDR_SIZE);

			info[0] = ptr->pck_flg;
			info[1] = 1;

			/* Create a new event */
			lcp_push_evt(ctx, LCP_HINT, ptr->slot, &ptr->addr, 
					info, 2);

#if LCP_DEBUG
			printf("Recv HNT from %s (%d)\n",
					lcp_str_addr6(&cli), len);
#endif
		}
		/* KAL */
		if((hdr.cb & LCP_C_KAL) == LCP_C_KAL) {
			time_t ti;

			time(&ti);
			ptr->last_kalive = ti;
		}
	}
}


LCP_API void lcp_con_update(struct lcp_ctx *ctx)
{
	struct lcp_con *next;
	struct lcp_con *ptr;
	struct lcp_hdr hdr;
	struct lcp_pck_que *pck;
	char buf[512];
	time_t ti;
	int tmp;

	time(&ti);

	/* Process incoming packets */
	lcp_con_recv(ctx);

	ptr = ctx->con.tbl;
	while(ptr != NULL) {
		next = ptr->next;

		/*
		 * I could have used switch here, but doing so would have made
		 * a mess with the 80 char-line-limit. Therefore I'm using ifs
		 * here, to make it look better.
		 */

		/* Send JOI */
		if(ptr->status == 0x01 && ti >= ptr->tout) {
			ptr->tout = ti + 1;
			ptr->count++;

			if(ptr->count > 3) {
				lcp_push_evt(ctx, LCP_UNAVAILABLE, ptr->slot, 
						&ptr->addr, NULL, 0);

				ptr->status = 0;
				goto next;
			}

			buf[0] = (char)0xff;
			buf[1] = 0x01;
			memcpy(buf + 2, &ptr->proxy_id, 2);

			if(lcp_sock_send(&ctx->sock, ptr->slot, 
						&ctx->proxy_addr, buf, 4) < 0) {
				lcp_push_evt(ctx, LCP_FAILED, ptr->slot,
						&ptr->addr, buf,
						LCP_PROXY_HDR_SIZE);
				goto next;
			}

#if LCP_DEBUG
			printf("Send JOI to %s (%d)\n",
					lcp_str_addr6(&ptr->addr), len);
#endif

			goto next;
		}
		/* Send INI */
		if(ptr->status == 0x04 && ti >= ptr->tout) {
			ptr->tout = ti + 1;
			ptr->count++;

			if(ptr->count > 3) {
				lcp_push_evt(ctx, LCP_UNAVAILABLE, ptr->slot, 
						&ptr->addr, NULL, 0);

				ptr->status = 0;
				goto next;
			}

			hdr.id = 0;
			hdr.cb = LCP_C_INI;	  /* Send INI-packet  */
			hdr.flg = ptr->pck_flg;
			memcpy(buf, &hdr, LCP_HDR_SIZE);

			tmp = LCP_HDR_SIZE;
			if((hdr.flg & LCP_F_ENC) == LCP_F_ENC) {
				mpz_export(buf + 4, NULL, 1, sizeof(char), 0, 
						0, ctx->pub.n);
				mpz_export(buf + 132, NULL, 1, sizeof(char), 0,
						0, ctx->pub.e);

				tmp = 133;
			}

			if(lcp_con_send(ctx, ptr, buf, tmp) < 0) {
				lcp_push_evt(ctx, LCP_FAILED, ptr->slot,
						&ptr->addr, buf, tmp);
				goto next;
			}

#if LCP_DEBUG
			printf("Send INI to %s (%d)\n",
					lcp_str_addr6(&ptr->addr), len);
#endif

			goto next;
		}
		/* Send INI-ACK */
		if(ptr->status == 0x05 && ti >= ptr->tout) {
			ptr->tout = ti + 1;
			ptr->count++;

			if(ptr->count > 3) {
				lcp_push_evt(ctx, LCP_UNAVAILABLE, ptr->slot, 
						&ptr->addr, NULL, 0);

				ptr->status = 0;
				goto next;
			}

			hdr.id = 0;
			hdr.cb = LCP_C_INI | LCP_C_ACK;	  /* Send INI-packet  */
			hdr.flg = ptr->pck_flg;
			memcpy(buf, &hdr, LCP_HDR_SIZE);

			tmp = LCP_HDR_SIZE;
			if((hdr.flg & LCP_F_ENC) == LCP_F_ENC) {
				mpz_export(buf + 4, NULL, 1, sizeof(char), 0, 
						0, ctx->pub.n);
				mpz_export(buf + 132, NULL, 1, sizeof(char), 0,
						0, ctx->pub.e);

				tmp = 133;
			}

			if(lcp_con_send(ctx, ptr, buf, tmp) < 0) {
				lcp_push_evt(ctx, LCP_FAILED, ptr->slot,
						&ptr->addr, buf, tmp);
				goto next;
			}

#if LCP_DEBUG
			printf("Send INI-ACK to %s (%d)\n",
					lcp_str_addr6(&ptr->addr), len);
#endif

			goto next;
		}
		/* Send ACK, responding to INI-ACK */
		if(ptr->status == 0x06) {
			hdr.id = 0;
			hdr.cb = LCP_C_ACK;
			hdr.flg = ptr->pck_flg;
			memcpy(buf, &hdr, LCP_HDR_SIZE);

			if(lcp_con_send(ctx, ptr, buf, 4) < 0) {
				lcp_push_evt(ctx, LCP_FAILED, ptr->slot, 
						&ptr->addr, buf, LCP_HDR_SIZE);
				goto next;
			}

			/* Mark connection as established */
			ptr->status = 0x07;

			/* Create new event */
			lcp_push_evt(ctx, LCP_CONNECTED, ptr->slot, &ptr->addr, 
					NULL, 0);

#if LCP_DEBUG
			printf("Send ACK to %s (%d)\n",
					lcp_str_addr6(&ptr->addr), len);
#endif

			goto next;
		}
		/* Send FIN */
		if(ptr->status == 0x08 && ti >= ptr->tout) {	
			ptr->tout = ti + 1;
			ptr->count++;

			if(ptr->count > 3) {
				lcp_push_evt(ctx, LCP_TIMEDOUT, ptr->slot,
						&ptr->addr, NULL, 0);

				/* Remove connection */
				ptr->status = 0;
				goto next;
			}

			hdr.id = 0;
			hdr.cb = LCP_C_FIN;
			hdr.flg = ptr->pck_flg;
			memcpy(buf, &hdr, LCP_HDR_SIZE);

			if(lcp_con_send(ctx, ptr, buf, 4) < 0) {
				lcp_push_evt(ctx, LCP_FAILED, ptr->slot, 
						&ptr->addr, buf, LCP_HDR_SIZE);
				goto next;
			}

#if LCP_DEBUG
			printf("Send FIN to %s (%d)\n",
					lcp_str_addr6(&ptr->addr), len);
#endif

			goto next;
		}
		/* Send FIN-ACK */
		if(ptr->status == 0x09 && ti >= ptr->tout) {	
			ptr->tout = ti + 1;
			ptr->count++;

			if(ptr->count > 3) {
				lcp_push_evt(ctx, LCP_UNAVAILABLE, ptr->slot, 
						&ptr->addr, NULL, 0);

				ptr->status = 0;
				goto next;
			}

			hdr.id = 0;
			hdr.cb = LCP_C_FIN | LCP_C_ACK;
			hdr.flg = ptr->pck_flg;
			memcpy(buf, &hdr, LCP_HDR_SIZE);

			if(lcp_con_send(ctx, ptr, buf, 4) < 0) {
				lcp_push_evt(ctx, LCP_FAILED, ptr->slot, 
						&ptr->addr, buf, LCP_HDR_SIZE);
				goto next;
			}

#if LCP_DEBUG
			printf("Send FIN-ACK to %s (%d)\n",
					lcp_str_addr6(&ptr->addr), len);
#endif

			goto next;
		}
		/* Send ACK, responding to FIN-ACK */
		if(ptr->status == 0x0a) {
			hdr.id = 0;
			hdr.cb = LCP_C_ACK;
			hdr.flg = ptr->pck_flg;
			memcpy(buf, &hdr, LCP_HDR_SIZE);

			if(lcp_con_send(ctx, ptr, buf, 4) < 0) {
				lcp_push_evt(ctx, LCP_UNAVAILABLE, ptr->slot, 
						&ptr->addr, buf, LCP_HDR_SIZE);

				ptr->status = 0;
				continue;
			}


			/* If a proxy is used, disconnect from proxy */
			if(ptr->con_flg == LCP_CON_F_PROXY) {
				ptr->status = 0x0c;
				ptr->tout = ti;
				ptr->count = 0;
				continue;
			}

			/* Create new event */
			lcp_push_evt(ctx, LCP_DISCONNECTED, ptr->slot,
					&ptr->addr, NULL, 0);

			/* Remove the entry from the connection-list */
			lcp_con_remv(ctx, &ptr->addr);

#if LCP_DEBUG
			printf("Send ACK to %s (%d)\n",
					lcp_str_addr6(&ptr->addr), len);
#endif

			goto next;
		}
		/* Send LEA to proxy */
		if(ptr->status == 0x0c && ti >= ptr->tout) {
			ptr->tout = ti + 1;
			ptr->count++;

			if(ptr->count > 3) {
				lcp_push_evt(ctx, LCP_UNAVAILABLE, ptr->slot, 
						&ptr->addr, NULL, 0);

				/* Remove connection */
				ptr->status = 0;
				goto next;
			}

			buf[0] = (char)0xff;
			buf[1] = 0x02;
			memcpy(buf + 2, &ptr->proxy_id, 2);

			if(lcp_sock_send(&ctx->sock, ptr->slot, 
						&ctx->proxy_addr, buf, 4) < 0) {
				lcp_push_evt(ctx, LCP_FAILED, ptr->slot, 
						&ptr->addr, buf, 
						LCP_PROXY_HDR_SIZE);
				goto next;
			}

#if LCP_DEBUG
			printf("Send LEA to %s (%d)\n",
					lcp_str_addr6(&ptr->addr), len);
#endif

			goto next;
		}
		/* Send HNT */
		if(ptr->status == 0x0d && ti >= ptr->tout) {
			struct lcp_hdr proto_hdr;

			ptr->tout = ti + 1;
			ptr->count++;

			/* Failed to send hint */
			if(ptr->count > 3) {
				lcp_push_evt(ctx, LCP_TIMEDOUT, ptr->slot, 
						&ptr->addr, NULL, 0);

				ptr->status = 0x07;
				goto next;
			}

			proto_hdr.id = 0;
			proto_hdr.cb = LCP_C_HNT;
			proto_hdr.flg = ptr->pck_flg;
			memcpy(buf, &proto_hdr, LCP_HDR_SIZE);

			if(lcp_con_send(ctx, ptr, buf, LCP_HDR_SIZE) < 0) {
				lcp_push_evt(ctx, LCP_FAILED, ptr->slot, 
						&ptr->addr, buf, LCP_HDR_SIZE);
				goto next;
			}

#if LCP_DEBUG
			printf("Send HNT to %s (%d)\n",
					lcp_str_addr6(&ptr->addr), len);
#endif

			goto next;
		}


		time(&ti);

		/* Check if connection timed out */
		if(ti > ptr->last_kalive + 14) {
			lcp_push_evt(ctx, LCP_TIMEDOUT, ptr->slot, 
					&ptr->addr, NULL, 0);
		}

		/* Send a keepalive message */
		if(ti >= ptr->kalive) {
			lcp_sendto(ctx, &ptr->addr, LCP_C_KAL, NULL, 0);
			ptr->kalive = ti + 3;
		}

		/* Send or resend packets from the packet-queue */
		pck = ptr->que;
		while(pck != NULL) {
			if(ti >= pck->tout) {
				pck->tout = ti + 1;
				pck->count++;

				if(pck->count > 3) {
					lcp_push_evt(ctx, LCP_FAILED,
							ptr->slot, &ptr->addr,
							NULL, 0);

					/* Remove package from the package-list */
					lcp_que_remv(ptr, pck);
					continue;
				}

				if(lcp_con_send(ctx, ptr, pck->buf, 
							pck->len) < 0) {
					lcp_push_evt(ctx, LCP_FAILED, 
							ptr->slot, &ptr->addr, 
							pck->buf, pck->len);
					goto next;
				}
			}

			pck = pck->next;
		}

next:
		ptr = next;
	}
}


LCP_API int lcp_con_send(struct lcp_ctx *ctx, struct lcp_con *con, char *buf, 
		int len)
{
	char *pck_buf;
	int pck_len;
	struct sockaddr_in6 *addr;
	int ret;

	if((con->con_flg & LCP_CON_F_DIRECT) == LCP_CON_F_DIRECT) {
		pck_buf = buf;
		pck_len = len;

		addr = &con->addr;
	}
	else {
		pck_len = len + 4;
		if(!(pck_buf = malloc(pck_len)))
			return -1;

		pck_buf[0] = (char)0xff;
		pck_buf[1] = 0x03;
		memcpy(pck_buf + 2, &con->proxy_id, 2);

		memcpy(pck_buf + 4, buf, len);

		addr = &ctx->proxy_addr;
	}

	ret = lcp_sock_send(&ctx->sock, con->slot, addr, pck_buf, pck_len);

	if((con->con_flg & LCP_CON_F_DIRECT) != LCP_CON_F_DIRECT)
		free(pck_buf);

	return ret;
}


LCP_API struct lcp_con *lcp_con_sel_addr(struct lcp_ctx *ctx, 
		struct sockaddr_in6 *addr)
{
	struct lcp_con *ptr;

	ptr = ctx->con.tbl;
	while(ptr != NULL) {
		if(memcmp(&ptr->addr.sin6_addr, &addr->sin6_addr, 16) == 0 &&
				ptr->addr.sin6_port == addr->sin6_port)
			return ptr;

		ptr = ptr->next;
	}

	return NULL;
}


LCP_API struct lcp_con *lcp_con_sel_proxy(struct lcp_ctx *ctx, uint16_t id)
{
	struct lcp_con *ptr;

	ptr = ctx->con.tbl;
	while(ptr != NULL) {
		if(ptr->proxy_id == id && ptr->con_flg == LCP_CON_F_PROXY)
			return ptr;

		ptr = ptr->next;
	}

	return NULL;
}


LCP_API void lcp_con_print(struct lcp_ctx *ctx)
{
	struct lcp_con *ptr;
	int i = 0;
	short port;

	printf("Connections:\n");

	ptr = ctx->con.tbl;
	while(ptr != NULL) {
		port = ctx->sock.int_port[ptr->slot];

		printf("[%02x]: Flg: %02x, Port: %d(%d), Dst: %s\n",
				i, ptr->con_flg, ntohs(port), ptr->slot,
				lcp_str_addr6(&ptr->addr));

		i++;
		ptr = ptr->next;
	}

	if(i == 0)
		printf("No connections\n");
}


LCP_API int lcp_que_add(struct lcp_con *con, char *buf, int len, uint16_t id)
{
	struct lcp_pck_que *pck;
	time_t ti;

	time(&ti);

	if(buf == NULL || len <= 0)
		return -1;

	/* Allocate memory for the new entry */
	if(!(pck = malloc(sizeof(struct lcp_pck_que))))
		return -1;

	pck->prev = NULL;
	pck->next = NULL;
	pck->id = id;
	pck->count = 0;
	pck->tout = 0;

	/* Copy buffer */
	if(!(pck->buf = malloc(len)))
		goto err_free_pck;

	memcpy(pck->buf, buf, len);
	pck->len = len;

	if(con->que == NULL) {
		con->que = pck;
	}
	else {
		struct lcp_pck_que *ptr;

		ptr = con->que;
		while(ptr->next != NULL)
			ptr = ptr->next;

		pck->prev = ptr;
		ptr->next = pck;
	}
	return 0;

err_free_pck:
	free(pck);
	return -1;
}


LCP_API void lcp_que_remv(struct lcp_con *con, struct lcp_pck_que *ele)
{
	struct lcp_pck_que *prev;
	struct lcp_pck_que *next;

	if(con == NULL || ele == NULL)
		return;

	prev = ele->prev;
	next = ele->next;

	if(next != NULL)
		next->prev = prev;

	if(ele->prev != NULL)
		prev->next = ele->next;
	else
		con->que = next;

	free(ele->buf);
	free(ele);
}


LCP_API struct lcp_pck_que *lcp_que_sel(struct lcp_con *con, uint16_t id)
{
	struct lcp_pck_que *ptr;

	ptr = con->que;
	while(ptr != NULL) {
		if(memcmp(&ptr->id, &id, 2) == 0)
			return ptr;

		ptr = ptr->next;
	}

	return NULL;
}
