#include "lcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ifaddrs.h>


/* Initialize the server-addresses for the DISCO- and PROXY-server */
LCP_INTERN int lcp_init_addr(struct lcp_ctx *ctx)
{
	int size = sizeof(struct sockaddr_in6);

	memset(&ctx->disco_addr, 0, size);
	ctx->disco_addr.sin6_family = AF_INET6;
	ctx->disco_addr.sin6_port = htons(DISCO_PORT);
	if(inet_pton(AF_INET6, DISCO_IP, &ctx->disco_addr.sin6_addr) < 0)
		return -1;

	memset(&ctx->proxy_addr, 0, size);
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
	int size = sizeof(struct sockaddr_in6);
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
	memset(&cli, 0, size);
	cli.sin6_family = AF_INET6;
	cli.sin6_port = htons(port);
	cli.sin6_addr = in6addr_any;
	if(bind(sockfd, cli_ptr, size) < 0)
		goto err_close_sockfd;

	serv_ptr = (struct sockaddr *)&ctx->disco_addr;

	/* Send a request to the stun-server */
	if(sendto(sockfd, "hi\0", 3, 0, serv_ptr, size) < 0)
		goto err_close_sockfd;

	/* Listen for a response from the server */
	if(recvfrom(sockfd, &res, size, 0, NULL, NULL) < 0)
		goto err_close_sockfd;

	/* Copy the LCP_APIal IPv6-address and port */
	ctx->ext_addr = res.sin6_addr;

	if(ntohs(res.sin6_port) == port) {
		ctx->flg = ctx->flg | LCP_F_PPR;
	}

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

LCP_API struct lcp_ctx *lcp_init(short base, short num)
{
	struct lcp_ctx *ctx;

	if(!(ctx = malloc(sizeof(struct lcp_ctx))))
		return NULL;

	/* Set initial values of variables of the context */
	ctx->flg = LCP_F_OPEN;
	ctx->evt = NULL;

	/* Set the initial values of the connection-list */
	ctx->con.tbl = NULL;
	ctx->con.num = 0;

	/* Initialize the default server-addresses */
	if(lcp_init_addr(ctx) < 0)
		goto err_free_ctx;

	/* Discover the LCP_APIal address and test port preservation */
	if(lcp_discover(ctx) < 0)
		goto err_free_ctx;

	/* Discover the internal address */
	if(lcp_get_intern(ctx) < 0)
		goto err_free_ctx;

	/* Initialize the socket-table */
	if(lcp_sock_init(&ctx->sock, ctx->flg, &ctx->upnp, base, num) < 0)
		goto err_free_ctx;

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
	lcp_sock_close(&ctx->sock, ctx->flg, &ctx->upnp);

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


LCP_API short lcp_connect(struct lcp_ctx *ctx, short port, 
		struct sockaddr_in6 *dst, uint8_t flg)
{
	short slot;
	struct lcp_sock_tbl *tbl = &ctx->sock;

	if(port >= 0) {
		if((slot = lcp_sel_port(tbl, port)) < 0)
			return -1;

		if(tbl->mask[slot] == 0)
			return -1;

		if((ctx->flg & LCP_F_UPNP) == LCP_F_UPNP && 
				tbl->con_c[slot] > 0)
			return -1;
	}
	else {
		if(lcp_sock_get_open(tbl, ctx->flg, &slot, 1) < 1)
			return -1;
	}

	/* Add a new connection to the connection-table */
	if(!lcp_con_add(ctx, dst, slot, flg))
		return -1;

	return slot;
}


LCP_API int lcp_disconnect(struct lcp_ctx *ctx, struct sockaddr_in6 *addr)
{
	struct lcp_con *ptr;

	if(!(ptr = lcp_con_sel_addr(ctx, addr)))
		return -1;

	ptr->status = 0x05;
	return 0;
}


LCP_API void lcp_update(struct lcp_ctx *ctx)
{
	/* Update the socket-table */
	lcp_sock_update(&ctx->sock, ctx->flg, &ctx->upnp);

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
	if((con->flg & LCP_F_ENC) == LCP_F_ENC) {
		printf("Use encryption\n");
		lcp_encrypt(&cont_buf, &cont_len, buf, len, con->pub);
	}
	else {
		cont_buf = buf;
		cont_len = len;
	}

	/* Allocate memory for the packet */
	pck_len = cont_len + sizeof(struct lcp_hdr);
	if(!(pck_buf = malloc(pck_len)))
		return -1;

	/* Set the packet-header */
	hdr.id = id;
	hdr.cb = LCP_C_PSH;
	/* TODO: Change flag */
	hdr.flg = con->flg;

	/* Copy everything into the packet-buffer */
	memcpy(pck_buf, &hdr, sizeof(struct lcp_hdr));
	memcpy(pck_buf + sizeof(struct lcp_hdr), cont_buf, cont_len);

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

	if(!(con = malloc(sizeof(struct lcp_con))))
		return NULL;

	con->next = NULL;
	con->addr = *dst;
	con->slot = slot; 

	con->flg = flg;
	con->que = NULL;

	con->status = 0;
	con->count = 0;
	con->tout = ti + 1;

	/* Setup public key */
	lcp_init_pub(&con->pub);

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
	int size = sizeof(struct sockaddr_in6);

	prev = NULL;
	ptr = ctx->con.tbl;

	while(ptr != NULL) {
		if(memcmp(&ptr->addr, addr, size) == 0) {
			/* Decrement the number of connections using socket */
			ctx->sock.con_c[ptr->slot]--;	

			if(prev == NULL)
				ctx->con.tbl = ptr->next;
			else
				prev->next = ptr->next;

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
	int len;
	short slot;
	time_t ti;
	struct sockaddr_in6 cli;

	time(&ti);

	while(lcp_recv(sock, buf, 512, &len, &cli, &slot)) {
		buf[len] = 0;

		/* Drop packet if it'S to short */
		if(len < sizeof(struct lcp_hdr))
			continue;

		memcpy(&hdr, buf, sizeof(struct lcp_hdr));
		ptr = lcp_con_sel_addr(ctx, &cli);

		/* INI */
		if((hdr.cb & LCP_C_INI) == LCP_C_INI) {
			/* INI-ACK */
			if(hdr.cb & LCP_C_ACK) {
				char n[128];
				char e[1];
				int tmp = sizeof(char);

				printf("Recv INI-ACK\n");

				if(ptr->status >= 0x02)
					continue;

				/* Read public-key */
				memcpy(n, buf + 4, 128);
				memcpy(e, buf + 132, 1);

				mpz_import(ptr->pub.n, 128, 1, tmp, 0, 0, n);
				mpz_import(ptr->pub.e, 1, 1, tmp, 0, 0, e);

				/* Require socket to send ACK */
				ptr->status = 0x02;
			}
			/* Just INI */
			else {
				char n[128];
				char e[1];
				int tmp = sizeof(char);

				printf("Recv INI\n");

				if(ptr != NULL) {
					continue;
				}

				/* Push new entry into the connection-list */
				con = lcp_con_add(ctx, &cli, slot, hdr.flg);

				if(con == NULL) {
					/* TODO: Reset  connection*/
				}

				/* Read public-key */
				memcpy(n, buf + 4, 128);
				memcpy(e, buf + 132, 1);

				mpz_import(con->pub.n, 128, 1, tmp, 0, 0, n);
				mpz_import(con->pub.e, 1, 1, tmp, 0, 0, e);

				/* Require socket to send INI-ACK */
				con->status = 0x01;
				con->tout = ti + 1;
				con->count = 0;
			}

			continue;	
		}
		/* FIN */
		if((hdr.cb & LCP_C_FIN) == LCP_C_FIN) {
			/* FIN-ACK */
			if(hdr.cb & LCP_C_ACK) {
				printf("Recv FIN-ACK\n");

				if(ptr->status >= 0x06)
					continue;

				/* Require socket to send ACK */
				ptr->status = 0x06;
			}
			/* Just FIN */
			else {
				printf("Recv FIN\n");

				if(ptr == NULL)
					continue;

				/* Require socket to send FIN-ACK */
				ptr->status = 0x05;
				con->tout = ti + 1;
				con->count = 0;
			}
			continue;
		}
		/* ACK */
		if((hdr.cb & LCP_C_ACK) == LCP_C_ACK) {
			struct lcp_pck_que *pck;

			/* Acknowledge new connection */
			if(ptr->status == 0x01) {
				printf("Recv ACK\n");

				ptr->status = 0x03;

				/* Create new event */
				lcp_push_evt(ctx, LCP_CONNECTED, ptr->slot, 
						&ptr->addr, NULL, 0);

				continue;
			}

			/* Acknowledge closing a connection */
			if(ptr->status == 0x05) {
				printf("Recv ACK\n");

				/* Create a new event */
				lcp_push_evt(ctx, LCP_DISCONNECTED, ptr->slot,
						&ptr->addr, NULL, 0);

				/* Remove the entry from the connection-list */
				lcp_con_remv(ctx, &ptr->addr);

				continue;
			}

			memcpy(&hdr, buf, sizeof(struct lcp_hdr));
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

			if((hdr.flg & LCP_F_ENC) == LCP_F_ENC) {
				lcp_decrypt(&cont_buf, &cont_len, buf + tmp, 
						len - tmp, ctx->pvt);
			}
			else {
				cont_buf = buf + tmp;
				cont_len = len - tmp;
			}

			/* Create new event */
			lcp_push_evt(ctx, LCP_RECEIVED, ptr->slot, &ptr->addr, 
					cont_buf, cont_len);	

			/* Send an acknowledgement for the packet */
			hdr.cb = LCP_C_ACK;
			sockfd = ctx->sock.fd[ptr->slot];
			sendto(sockfd, &hdr, tmp, 0, (struct sockaddr *)&ptr->addr,
					sizeof(struct sockaddr_in6));
		}
	}
}


LCP_API void lcp_con_update(struct lcp_ctx *ctx)
{
	struct lcp_con *next;
	struct lcp_con *ptr;
	struct lcp_hdr hdr;
	struct lcp_sock_tbl *sock = &ctx->sock;
	struct lcp_pck_que *pck;
	char buf[512];
	time_t ti;
	int tmp;

	time(&ti);	

	lcp_con_recv(ctx);

	ptr = ctx->con.tbl;
	while(ptr != NULL) {
		next = ptr->next;

		/*
		 * I could have used switch here, but doing so would have made
		 * a mess with the 80 char-line-limit. Therefore I'm using ifs
		 * here, to make it look better.
		 */

		/* Send INI */
		if(ptr->status == 0x00 && ti >= ptr->tout) {
			ptr->tout = ti + 1;
			ptr->count++;

			if(ptr->count > 3) {
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

			if(lcp_sock_send(sock, ptr->slot, &ptr->addr, buf, 133) < 0) {
				/* Failed to send initial-packet */
			}

			printf("Send INI\n");
			goto next;
		}
		/* Send INI-ACK */
		if(ptr->status == 0x01 && ti >= ptr->tout) {
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

			if(lcp_sock_send(sock, ptr->slot, &ptr->addr, buf, 133) < 0) {
				/* Failed to send initial-packet */
			}

			printf("Send INI-ACK\n");
			goto next;
		}
		/* Send ACK, responding to INI-ACK */
		if(ptr->status == 0x02) {
			hdr.id = 0;
			hdr.cb = LCP_C_ACK;
			hdr.flg = ptr->flg;
			memcpy(buf, &hdr, sizeof(struct lcp_hdr));

			if(lcp_sock_send(sock, ptr->slot, &ptr->addr, buf, 4) < 0) {
				/* Failed to send acknowledge-packet */
			}

			/* Mark connection as established */
			ptr->status = 0x03;

			/* Create new event */
			lcp_push_evt(ctx, LCP_CONNECTED, ptr->slot, &ptr->addr, 
					NULL, 0);

			printf("Send ACK\n");
			goto next;
		}
		/* Send FIN */
		if(ptr->status == 0x04 && ti >= ptr->tout) {	
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

			if(lcp_sock_send(sock, ptr->slot, &ptr->addr, buf, 4) < 0) {
				/* Failed to send closing-request */
			}

			printf("Send FIN\n");
			goto next;
		}
		/* Send FIN-ACK */
		if(ptr->status == 0x05 && ti >= ptr->tout) {	
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

			if(lcp_sock_send(sock, ptr->slot, &ptr->addr, buf, 4) < 0) {
				/* Failed to send acknowledge-packet */
			}

			printf("Send FIN-ACK\n");
			goto next;
		}
		/* Send ACK, responding to FIN-ACK */
		if(ptr->status == 0x06) {
			hdr.id = 0;
			hdr.cb = LCP_C_ACK;
			hdr.flg = ptr->flg;
			memcpy(buf, &hdr, sizeof(struct lcp_hdr));

			if(lcp_sock_send(sock, ptr->slot, &ptr->addr, buf, 4) < 0) {
				/* Failed to send acknowledge-packet */
			}

			/* Create new event */
			lcp_push_evt(ctx, LCP_DISCONNECTED, ptr->slot,
					&ptr->addr, NULL, 0);

			/* Remove the entry from the connection-list */
			lcp_con_remv(ctx, &ptr->addr);

			printf("Send ACK\n");
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

				lcp_sock_send(sock, ptr->slot, &ptr->addr, 
						pck->buf, pck->len);
			}

			pck = pck->next;
		}

next:
		ptr = next;
	}
}


LCP_API struct lcp_con *lcp_con_sel_addr(struct lcp_ctx *ctx, 
		struct sockaddr_in6 *addr)
{
	struct lcp_con *ptr;
	int size = sizeof(struct sockaddr_in6);

	ptr = ctx->con.tbl;
	while(ptr != NULL) {
		if(memcmp(&ptr->addr, addr, size) == 0) {
			return ptr;
		}
		ptr = ptr->next;
	}

	return NULL;
}


LCP_API void lcp_con_print(struct lcp_ctx *ctx)
{
	struct lcp_con *ptr;
	int i = 0;

	ptr = ctx->con.tbl;
	while(ptr != NULL) {
		printf("Connection %d: %p\n", i, (void *)ptr->next);

		i++;
		ptr = ptr->next;
	}
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
		if(ptr->id == id) {
			return ptr;
		}
	}

	return NULL;
}
