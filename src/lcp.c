#include "lcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ifaddrs.h>

#define ADDR6_SIZE sizeof(struct sockaddr_in6)

/* Initialize the server-addresses for the DISCO- and PROXY-server */
LCP_INTERN int lcp_init_addr(struct lcp_ctx *ctx)
{
	memset(&ctx->disco_addr, 0, ADDR6_SIZE);
	ctx->disco_addr.sin6_family = AF_INET6;
	ctx->disco_addr.sin6_port = htons(DISCO_PORT);
	if(inet_pton(AF_INET6, DISCO_IP, &ctx->disco_addr.sin6_addr) < 0)
		return -1;

	memset(&ctx->proxy_addr, 0, ADDR6_SIZE);
	ctx->proxy_addr.sin6_family = AF_INET6;
	ctx->proxy_addr.sin6_port = htons(PROXY_PORT);
	if(inet_pton(AF_INET6, PROXY_IP, &ctx->proxy_addr.sin6_addr) < 0)
		return -1;

	return 0;
}


/* Get the LCP_APIal address and check if port preservation is enabled */
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
	if(sendto(sockfd, "hi\0", 3, 0, serv_ptr, ADDR6_SIZE) < 0)
		goto err_close_sockfd;

	/* Listen for a response from the server */
	if(recvfrom(sockfd, &res, ADDR6_SIZE, 0, NULL, NULL) < 0)
		goto err_close_sockfd;

	/* Copy the external IPv6-address and port */
	ctx->ext_addr = res.sin6_addr;

	/* Check if port-preservation is enabled */
	if(ntohs(res.sin6_port) == port)
		ctx->flg = ctx->flg | LCP_NET_F_PPR;

	/* Check if uPnP is enabled */
	if(lcp_upnp_prep(&ctx->upnp) == 0)
		ctx->flg = ctx->flg | LCP_NET_F_UPNP;

	/* Check if direct connection are possible */
	if(ctx->flg > 0)
		ctx->flg = ctx->flg | LCP_CON_F_DIRECT;

	close(sockfd);
	return 0;

err_close_sockfd:
	close(sockfd);
	return -1;
}


/* Get the internal address */
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
		printf("Use overwrite\n");

		/* Set initial values of variables of the context */
		ctx->flg = ovw;
		ctx->evt = NULL;

		/* Set the initial values of the connection-list */
		ctx->con.tbl = NULL;
		ctx->con.num = 0;
	}
	else {
		printf("Don't use overwrite\n");

		/* Set initial values of variables of the context */
		ctx->flg = 0;
		ctx->evt = NULL;

		/* Set the initial values of the connection-list */
		ctx->con.tbl = NULL;
		ctx->con.num = 0;

		/* Initialize the default server-addresses */
		if(lcp_init_addr(ctx) < 0)
			goto err_free_ctx;

		printf("Init address\n");

		if(disco != NULL)
			ctx->disco_addr = *disco;
		if(proxy != NULL)
			ctx->proxy_addr = *proxy;

		/* Discover the external address and test port preservation */
		if(lcp_discover(ctx) < 0)
			goto err_free_ctx;

		printf("Discover\n");

		/* Discover the internal address */
		if(lcp_get_intern(ctx) < 0)
			goto err_free_ctx;

		printf("Intern\n");

	}

	/* Initialize the socket-table */
	if(lcp_sock_init(&ctx->sock, ctx->flg, &ctx->upnp, base, num) < 0)
		goto err_free_ctx;

	printf("Init intern\n");

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

	/* Free the context-struct */
	free(ctx);
}


LCP_API int lcp_get_slot(struct lcp_ctx *ctx)
{
	int i;

	for(i = 0; i < LCP_SOCK_NUM; i++) {
		if(ctx->sock.mask[i] == 0)
			return i;
	}

	return -1;
}


LCP_API struct lcp_con *lcp_connect(struct lcp_ctx *ctx, short port, 
		struct sockaddr_in6 *dst, uint8_t flg)
{
	short slot;
	int tmp;
	struct lcp_sock_tbl *tbl = &ctx->sock;
	struct lcp_con *con;

	if(port >= 0) {
		printf("Select port\n");
		if((slot = lcp_sock_sel_port(tbl, port)) < 0)
			return NULL;

		printf("Check mask\n");
		if(tbl->mask[slot] == 0)
			return NULL;

		printf("Check network\n");
		if((ctx->flg & LCP_NET_F_UPNP) == LCP_NET_F_UPNP && 
				tbl->con_c[slot] > 0)
			return NULL;
	}
	else {
		if((tmp = lcp_sock_get_open(tbl, &slot, 1)) < 1)
			return NULL;
	}

	printf("Add new connection\n");

	/* Add a new connection to the connection-table */
	if(!(con = lcp_con_add(ctx, dst, slot, LCP_F_ENC | flg)))
		return NULL;

	/* Require connection send JOI */
	con->status = 0x01;

	printf("Flags %02x\n", flg);

	/* If a direct connection should be extablished, skip proxy */
	if((flg & LCP_CON_F_DIRECT) == LCP_CON_F_DIRECT) {
		printf("Use direct\n");

		/* Require connection to send INI */
		con->status = 0x04;
	}

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

	/* Require connection to send FIN */
	ptr->status = 0x08;
	return 0;
}


LCP_API void lcp_update(struct lcp_ctx *ctx)
{
	/* Update the socket-table */
	lcp_sock_update(&ctx->sock);

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
	int hdr_sz = sizeof(struct lcp_hdr);
	uint16_t id;
	struct lcp_con *con;

	/* Get the id of the packet */
	/* TODO: Replace with better id-number */
	id = rand() % 0xffff;

	/* Get the connection */
	if(!(con = lcp_con_sel_addr(ctx, addr)))
		return -1;

	/* If encryption should be used */
	if((con->flg & LCP_F_ENC) == LCP_F_ENC) {
#if LCP_DEBUG
		printf("Use encryption\n");
#endif
		lcp_encrypt(&cont_buf, &cont_len, buf, len, con->pub);
	}
	else {
		cont_buf = buf;
		cont_len = len;
	}

	/* Allocate memory for the packet */
	pck_len = cont_len + hdr_sz;
	if(!(pck_buf = malloc(pck_len)))
		return -1;

	/* Set the packet-header */
	hdr.id = id;
	hdr.cb = LCP_C_PSH;
	/* TODO: Change flag */
	hdr.flg = con->flg;

	/* Copy everything into the packet-buffer */
	memcpy(pck_buf, &hdr, hdr_sz);
	memcpy(pck_buf + hdr_sz, cont_buf, cont_len);

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


LCP_API struct lcp_con *lcp_con_add(struct lcp_ctx *ctx, 
		struct sockaddr_in6 *dst, short slot, uint8_t flg)
{
	struct lcp_con_lst *tbl = &ctx->con;
	struct lcp_con *con;
	struct lcp_con *ptr;
	time_t ti;

	time(&ti);

	printf("New connection using: %02x\n", flg);

	if(!(con = malloc(sizeof(struct lcp_con))))
		return NULL;

	con->next = NULL;
	con->addr = *dst;
	con->slot = slot; 

	con->flg = flg;
	con->que = NULL;

	con->count = 0;
	con->tout = 0;

	con->proxy_id = 0;

	/* Setup public key */
	lcp_init_pub(&con->pub);

	/* Update the socket */
	if((ctx->flg & LCP_NET_F_PPR) == LCP_NET_F_PPR) {
		ctx->sock.mask[slot] += LCP_SOCK_M_KEEPALIVE;

		if((flg & LCP_CON_F_DIRECT) != LCP_CON_F_DIRECT)
			ctx->sock.dst[slot] = ctx->proxy_addr;
		else
			ctx->sock.dst[slot] = *dst;

		ctx->sock.tout[slot] = ti;
		printf("Modified socket mask\n");
	}

	/* Increment the number of connections using socket */
	ctx->sock.con_c[slot]++;

	if(tbl->tbl == NULL) {
		printf("Set root\n");

		tbl->tbl = con;
		tbl->num = 1;
	}
	else {
		printf("Append\n");

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

			/* Update the socket */
			if((ctx->flg & LCP_NET_F_PPR) == LCP_NET_F_PPR) {
				ctx->sock.mask[ptr->slot] -= 
					LCP_SOCK_M_KEEPALIVE;
			}

			lcp_clear_pub(&ptr->pub);

			/* TODO: Clear packet-queue */

			free(ptr);
			ctx->con.num--;
			return;
		}

		prev = ptr;
		ptr = ptr->next;
	}
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

				printf("Wait other link to join link\n");
				continue;
			}
			/* 
			 * Other link connected to the link, initiate new
			 * connection.
			 */
			else if(buf_ptr[1] == 0x04 && ptr->status == 0x02) {
				/* Require connection send INI */
				ptr->status = 0x04;

				printf("Link complete\n");
				continue;
			}

			/* Skip the proxy-header */
			buf_ptr += 4;
		}
		else {
			ptr = lcp_con_sel_addr(ctx, &cli);
		}

		/* Get header from buffer */
		memcpy(&hdr, buf_ptr, sizeof(struct lcp_hdr));

		/* INI */
		if((hdr.cb & LCP_C_INI) == LCP_C_INI) {
			/* INI-ACK */
			if(hdr.cb & LCP_C_ACK) {
				char n[128];
				char e[1];
				int tmp = sizeof(char);

				if(ptr == NULL)
					continue;

#if LCP_DEBUG
				printf("Recv INI-ACK\n");
#endif

				if(ptr->status >= 0x06)
					continue;

				/* Read public-key */
				memcpy(n, buf_ptr + 4, 128);
				memcpy(e, buf_ptr + 132, 1);

				mpz_import(ptr->pub.n, 128, 1, tmp, 0, 0, n);
				mpz_import(ptr->pub.e, 1, 1, tmp, 0, 0, e);

				/* Require connection to send ACK */
				ptr->status = 0x06;
			}
			/* Just INI */
			else {
				char n[128];
				char e[1];
				int tmp = sizeof(char);

#if LCP_DEBUG
				printf("Recv INI\n");
#endif

				if(ptr != NULL) {
					if(ptr->status > 0x04)
						continue;

					con = ptr;
				}
				else {
					/* Push new entry in connection-list */
					con = lcp_con_add(ctx, &cli, slot,
							hdr.flg);

					if(con == NULL) {
						/* TODO: Reset  connection*/
					}
				}

				/* Read public-key */
				memcpy(n, buf_ptr + 4, 128);
				memcpy(e, buf_ptr + 132, 1);

				mpz_import(con->pub.n, 128, 1, tmp, 0, 0, n);
				mpz_import(con->pub.e, 1, 1, tmp, 0, 0, e);

				/* Require connection to send INI-ACK */
				con->status = 0x05;
				con->tout = ti + 1;
				con->count = 0;
			}

			continue;	
		}
		/* FIN */
		if((hdr.cb & LCP_C_FIN) == LCP_C_FIN) {
			/* FIN-ACK */
			if(hdr.cb & LCP_C_ACK) {
#if LCP_DEBUG
				printf("Recv FIN-ACK\n");
#endif

				if(ptr->status >= 0x0a)
					continue;

				/* Require connection to send ACK */
				ptr->status = 0x0a;
			}
			/* Just FIN */
			else {
#if LCP_DEBUG
				printf("Recv FIN\n");
#endif

				if(ptr == NULL)
					continue;

				/* Require connection to send FIN-ACK */
				ptr->status = 0x09;
				ptr->tout = ti + 1;
				ptr->count = 0;
			}
			continue;
		}
		/* ACK */
		if((hdr.cb & LCP_C_ACK) == LCP_C_ACK) {
			struct lcp_pck_que *pck;

			/* Acknowledge new connection */
			if(ptr->status == 0x05) {
#if LCP_DEBUG
				printf("Recv ACK\n");
#endif

				/* Mark connection as established */
				ptr->status = 0x07;

				/* Create new event */
				lcp_push_evt(ctx, LCP_CONNECTED, ptr->slot, 
						&ptr->addr, NULL, 0);

				continue;
			}

			/* Acknowledge closing a connection */
			if(ptr->status == 0x09) {
#if LCP_DEBUG
				printf("Recv ACK\n");
#endif

				/* Create a new event */
				lcp_push_evt(ctx, LCP_DISCONNECTED, ptr->slot,
						&ptr->addr, NULL, 0);

				/* Remove the entry from the connection-list */
				lcp_con_remv(ctx, &ptr->addr);

				continue;
			}

			/* TODO: */
			/* memcpy(&hdr, buf_ptr, sizeof(struct lcp_hdr)); */
			if(!(pck = lcp_que_sel(ptr, hdr.id))) {
				/* No packet with that ID has been sent */
				continue;
			}

			if(pck->prev == NULL) {
				ptr->que = pck->next;
			}
			else {
				pck->prev->next = pck->next;
			}

			if(pck->buf != NULL)
				free(pck->buf);
			free(pck);
		}
		/* PSH */
		if((hdr.cb & LCP_C_PSH) == LCP_C_PSH) {
			int sockfd;
			int tmp = sizeof(struct lcp_hdr);
			char *cont_buf;
			int cont_len;
			struct sockaddr *addrp = (struct sockaddr *)&ptr->addr;

#if LCP_DEBUG
			printf("Recv PSH\n");
#endif

			if((hdr.flg & LCP_F_ENC) == LCP_F_ENC) {
				lcp_decrypt(&cont_buf, &cont_len, buf_ptr + tmp,
						len - tmp, ctx->pvt);
			}
			else {
				cont_buf = buf_ptr + tmp;
				cont_len = len - tmp;
			}

			/* Create new event */
			lcp_push_evt(ctx, LCP_RECEIVED, ptr->slot, &ptr->addr, 
					cont_buf, cont_len);	

			/* Send an acknowledgement for the packet */
			hdr.cb = LCP_C_ACK;
			sockfd = ctx->sock.fd[ptr->slot];
			sendto(sockfd, &hdr, tmp, 0, addrp, ADDR6_SIZE);
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
				printf("Failed to connect to proxy\n");

				/* Failed to initialize connection*/
				goto next;
			}

			buf[0] = 0xff;
			buf[1] = 0x01;
			memcpy(buf + 2, &ptr->proxy_id, 2);

			if(lcp_sock_send(&ctx->sock, ptr->slot, &ctx->proxy_addr, buf, 4) < 0) {
				printf("Failed to send JOI packet\n");

				goto next;
			}

#ifdef LCP_DEBUG
			printf("Send JOI\n");
#endif
			goto next;
		}

		/* Send INI */
		if(ptr->status == 0x04 && ti >= ptr->tout) {
			ptr->tout = ti + 1;
			ptr->count++;

			if(ptr->count > 3) {
				printf("Connection timed out\n");

				/* Failed to initialize connection*/
				goto next;
			}

			hdr.id = 0;
			hdr.cb = LCP_C_INI;	  /* Send INI-packet  */
			hdr.flg = ptr->flg;
			memcpy(buf, &hdr, sizeof(struct lcp_hdr));

			tmp = sizeof(char);
			mpz_export(buf + 4, NULL, 1, tmp, 0, 0, ctx->pub.n);
			mpz_export(buf + 132, NULL, 1, tmp, 0, 0, ctx->pub.e);

			if(lcp_con_send(ctx, ptr, buf, 133) < 0) {
				printf("Failed to send initial packet\n");
				/* Failed to send initial-packet */

				goto next;
			}

#if LCP_DEBUG
			printf("Send INI\n");
#endif
			goto next;
		}
		/* Send INI-ACK */
		if(ptr->status == 0x05 && ti >= ptr->tout) {
			ptr->tout = ti + 1;
			ptr->count++;

			if(ptr->count > 3) {
				/* Failed to acknowledge inital connection */
				goto next;
			}

			hdr.id = 0;
			hdr.cb = LCP_C_INI | LCP_C_ACK;	  /* Send INI-packet  */
			hdr.flg = ptr->flg;
			memcpy(buf, &hdr, sizeof(struct lcp_hdr));

			tmp = sizeof(char);
			mpz_export(buf + 4, NULL, 1, tmp, 0, 0, ctx->pub.n);
			mpz_export(buf + 132, NULL, 1, tmp, 0, 0, ctx->pub.e);

			if(lcp_con_send(ctx, ptr, buf, 133) < 0) {
				/* Failed to send initial-packet */
			}

#if LCP_DEBUG
			printf("Send INI-ACK\n");
#endif
			goto next;
		}
		/* Send ACK, responding to INI-ACK */
		if(ptr->status == 0x06) {
			hdr.id = 0;
			hdr.cb = LCP_C_ACK;
			hdr.flg = ptr->flg;
			memcpy(buf, &hdr, sizeof(struct lcp_hdr));

			if(lcp_con_send(ctx, ptr, buf, 4) < 0) {
				/* Failed to send acknowledge-packet */
			}

			/* Mark connection as established */
			ptr->status = 0x07;

			/* Create new event */
			lcp_push_evt(ctx, LCP_CONNECTED, ptr->slot, &ptr->addr, 
					NULL, 0);

#if LCP_DEBUG
			printf("Send ACK\n");
#endif
			goto next;
		}
		/* Send FIN */
		if(ptr->status == 0x08 && ti >= ptr->tout) {	
			ptr->tout = ti + 1;
			ptr->count++;

			if(ptr->count > 3) {
				/* Failed to close connection */
				goto next;
			}

			hdr.id = 0;
			hdr.cb = LCP_C_FIN;
			hdr.flg = ptr->flg;
			memcpy(buf, &hdr, sizeof(struct lcp_hdr));

			if(lcp_con_send(ctx, ptr, buf, 4) < 0) {
				/* Failed to send closing-request */
			}

#if LCP_DEBUG
			printf("Send FIN\n");
#endif
			goto next;
		}
		/* Send FIN-ACK */
		if(ptr->status == 0x09 && ti >= ptr->tout) {	
			ptr->tout = ti + 1;
			ptr->count++;

			if(ptr->count > 3) {
				/* Failed to close connection */
				goto next;
			}

			hdr.id = 0;
			hdr.cb = LCP_C_FIN | LCP_C_ACK;
			hdr.flg = ptr->flg;
			memcpy(buf, &hdr, sizeof(struct lcp_hdr));


			if(lcp_con_send(ctx, ptr, buf, 4) < 0) {
				/* Failed to send acknowledge-packet */
			}

#if LCP_DEBUG
			printf("Send FIN-ACK\n");
#endif
			goto next;
		}
		/* Send ACK, responding to FIN-ACK */
		if(ptr->status == 0x0a) {
			hdr.id = 0;
			hdr.cb = LCP_C_ACK;
			hdr.flg = ptr->flg;
			memcpy(buf, &hdr, sizeof(struct lcp_hdr));

			if(lcp_con_send(ctx, ptr, buf, 4) < 0) {
				/* Failed to send acknowledge-packet */
			}

			/* Create new event */
			lcp_push_evt(ctx, LCP_DISCONNECTED, ptr->slot,
					&ptr->addr, NULL, 0);

			/* Remove the entry from the connection-list */
			lcp_con_remv(ctx, &ptr->addr);

#if LCP_DEBUG
			printf("Send ACK\n");
#endif
			goto next;
		}

		pck = ptr->que;
		while(pck != NULL) {
			if(ti > pck->tout) {
				pck->tout = ti + 1;
				pck->count++;

				if(pck->count > 3) {
					/* Failed to send packet */
				}

				lcp_con_send(ctx, ptr, pck->buf, pck->len);
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

	if((con->flg & LCP_CON_F_DIRECT) == LCP_CON_F_DIRECT) {
#if LCP_DEBUG
		printf("Dont use proxy\n");
#endif
		pck_buf = buf;
		pck_len = len;

		addr = &con->addr;
	}
	else {
#if LCP_DEBUG
		printf("Use Proxy\n");
#endif

		pck_len = len + 4;
		if(!(pck_buf = malloc(pck_len)))
			return -1;

		pck_buf[0] = 0xff;
		pck_buf[1] = 0x03;
		memcpy(pck_buf + 2, &con->proxy_id, 2);

		memcpy(pck_buf + 4, buf, len);

		addr = &ctx->proxy_addr;
	}

	ret = lcp_sock_send(&ctx->sock, con->slot, addr, pck_buf, pck_len);

	if((con->flg & LCP_CON_F_DIRECT) != LCP_CON_F_DIRECT) {
		free(pck_buf);
	}

	return ret;
}


LCP_API struct lcp_con *lcp_con_sel_addr(struct lcp_ctx *ctx, 
		struct sockaddr_in6 *addr)
{
	struct lcp_con *ptr;

	ptr = ctx->con.tbl;
	while(ptr != NULL) {
		if(memcmp(&ptr->addr, addr, ADDR6_SIZE) == 0)
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
		if(ptr->proxy_id == id && (ptr->flg & 1) == 0)
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

		printf("[%02x]: Flg: %02x, Port: %d(%d), Dst: %s:%d\n",
				i, ptr->flg, port, ptr->slot,
				lcp_str_addr(AF_INET6, &ptr->addr.sin6_addr),
				ptr->addr.sin6_port);

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

	if(!(pck = malloc(sizeof(struct lcp_pck_que))))
		return -1;

	if(!(pck->buf = malloc(len)))
		goto err_free_pck;

	pck->prev = NULL;
	pck->next = NULL;
	pck->id = id;
	memcpy(pck->buf, buf, len);
	pck->len = len;

	pck->count = 0;
	pck->tout = ti;

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


LCP_API struct lcp_pck_que *lcp_que_sel(struct lcp_con *con, uint16_t id)
{
	struct lcp_pck_que *ptr;

	ptr = con->que;
	while(ptr != NULL) {
		if(ptr->id == id)
			return ptr;
	}

	return NULL;
}
