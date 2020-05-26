#include "lcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>


LCP_API void gen_keys(struct pvt_key *pvt, struct pub_key *pub)
{
	char buf[BUFFER_SIZE];
	int i;
	mpz_t phi;
	mpz_t tmp1;
	mpz_t tmp2; 

	mpz_init(phi);
	mpz_init(tmp1);
	mpz_init(tmp2);

	srand(time(NULL));

	mpz_set_ui(pvt->e, 3); 

	for(i = 0; i < BUFFER_SIZE; i++)
		buf[i] = rand() % 0xFF;

	buf[0] |= 0xC0;

	buf[BUFFER_SIZE - 1] |= 0x01;

	mpz_import(tmp1, BUFFER_SIZE, 1, sizeof(char), 0, 0, buf);

	mpz_nextprime(pvt->p, tmp1);

	mpz_mod(tmp2, pvt->p, pvt->e);
	while(!mpz_cmp_ui(tmp2, 1)) {
		mpz_nextprime(pvt->p, pvt->p);
		mpz_mod(tmp2, pvt->p, pvt->e);
	}

	do {
		for(i = 0; i < BUFFER_SIZE; i++)
			buf[i] = rand() % 0xFF;

		buf[0] |= 0xC0;
		buf[BUFFER_SIZE - 1] |= 0x01;
		mpz_import(tmp1, BUFFER_SIZE, 1, sizeof(char), 0, 0, buf);
		mpz_nextprime(pvt->q, tmp1);
		mpz_mod(tmp2, pvt->q, pvt->e);
		while(!mpz_cmp_ui(tmp2, 1)) {
			mpz_nextprime(pvt->q, pvt->q);
			mpz_mod(tmp2, pvt->q, pvt->e);
		}
	} while(mpz_cmp(pvt->p, pvt->q) == 0);

	mpz_mul(pvt->n, pvt->p, pvt->q);

	mpz_sub_ui(tmp1, pvt->p, 1);
	mpz_sub_ui(tmp2, pvt->q, 1);
	mpz_mul(phi, tmp1, tmp2);

	if(mpz_invert(pvt->d, pvt->e, phi) == 0) {
		mpz_gcd(tmp1, pvt->e, phi);
		printf("gcd(e, phi) = [%s]\n", mpz_get_str(NULL, 16, tmp1));
		printf("Invert failed\n");
	}

	mpz_set(pub->e, pvt->e);
	mpz_set(pub->n, pvt->n);

	mpz_clear(phi);
	mpz_clear(tmp1);
	mpz_clear(tmp2);
}


LCP_API void free_keys(struct pvt_key *pvt, struct pub_key *pub)
{
	if(pvt != NULL) {
		mpz_clear(pvt->n);
		mpz_clear(pvt->e);
		mpz_clear(pvt->d);
		mpz_clear(pvt->p);
		mpz_clear(pvt->q);
	}

	if(pub != NULL) {
		mpz_clear(pub->n);
		mpz_clear(pub->e);
	}
}


LCP_API int encrypt(char **out, int *out_len, char *in, int in_len, 
		struct pub_key pub)
{
	char *ret;
	char block[BLOCK_SIZE];
	mpz_t m;
	mpz_t c;

	int i = 0;
	int left = in_len;
	int num = (int)ceil((double)in_len / BUF_SIZE);
	int size = num * BLOCK_SIZE;

	if(!(ret = malloc(size)))
		return -1;

	memset(ret, 0, size);

	mpz_inits(m, c, NULL);

	while(left > 0) {
		int from = in_len - left;
		int to = (i + 1) * BLOCK_SIZE;
		int sz = (left > BUF_SIZE) ? (BUF_SIZE) : (left);
		size_t enc_len = 0;	

		memset(block, 0, BLOCK_SIZE);
		block[0] = 0x01;
		block[1] = 0x02;
		memcpy(block + 2, in + from, sz);

		mpz_import(m, BLOCK_SIZE, 1, sizeof(block[0]), 
				0, 0, block);

		mpz_powm(c, m, pub.e, pub.n);

		memset(block, 0, BLOCK_SIZE);

		mpz_export(block, &enc_len, 1, sizeof(char), 0, 0, c);

		memcpy(ret + to - enc_len, block, enc_len);

		left -= sz;
		i++;
	}

	*out = ret;
	*out_len = size;
	mpz_clears(m, c, NULL);
	return 0;
} 


LCP_API int decrypt(char **out, int *out_len, char *in, int in_len, 
		struct pvt_key pvt)
{
	int i;
	int num = in_len / BLOCK_SIZE;
	int msg_idx = 0;
	char block[BLOCK_SIZE];
	int size = num * BUF_SIZE;
	char *ret;
	mpz_t m;
	mpz_t c;

	if(!(ret = malloc(size)))
		return -1;

	memset(ret, 0, size);

	mpz_inits(m, c, NULL);

	for(i = 0; i < num; i++) {
		mpz_import(c, BLOCK_SIZE, 1, sizeof(char), 0, 0, 
				in + (i * BLOCK_SIZE));

		mpz_powm(m, c, pvt.d, pvt.n);

		mpz_export(block, NULL, 1, sizeof(char), 0, 0, m);

		memcpy(ret + (i * BUF_SIZE), block + 2, BUF_SIZE);
	}

	*out = ret;
	*out_len = size;
	mpz_clears(m, c, NULL);
	return msg_idx;
}


LCP_INTERN int lcp_push_evt(struct lcp_ctx *ctx, unsigned char type, 
		short slot, struct sockaddr_in6 *addr, unsigned int id,
		char *buf, int len)
{
	struct lcp_evt_ele *evt;

	if(!(evt = malloc(sizeof(struct lcp_evt_ele))))
		return -1;

	evt->next = NULL;
	evt->evt.type = type;
	evt->evt.slot = slot;
	evt->evt.addr = *addr;
	evt->evt.id = id;

	if(!(evt->evt.buf = malloc(len))) {
		free(evt);
		return -1;
	}

	memcpy(evt->evt.buf, buf, len);
	evt->evt.len = len;


	if(ctx->evt == NULL) {
		network.evt = evt;
		return 0;
	}
	else {
		struct lcp_evt_ele *ptr = ctx->evt;

		while(ptr != NULL) {
			if(ptr->next == NULL) {
				ptr->next = evt;
				return 0;
			}

			ptr = ptr->next;
		}
	}
	

	free(evt->evt.buf);
	free(evt);
	return -1;
}


LCP_API int lcp_pull_evt(struct lcp_ctx *ctx, struct lcp_evt *evt)
{
	struct lcp_evt_ele *ptr;

	if(evt == NULL)
		return -1;

	if(ctx->evt == NULL)
		return 0;

	*evt = ctx->evt->evt;
	ptr = ctx->evt->next;
	free(ctx->evt);
	ctx->evt = ptr;
	return 1;
}


LCP_API void lcp_del_evt(struct lcp_evt *evt)
{
	if(evt == NULL || evt->buf == NULL)
		return;

	free(evt->buf);
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


/* Initialize the socket-table */
static int lcp_sock_init(struct lcp_ctx *ctx)
{
	int i;
	int port;
	int sockfd;
	struct sockaddr_in6 addr;
	struct sockaddr *addr_ptr = (struct sockaddr *)&addr;
	int addr_sz = sizeof(addr);
	struct socket_table *tbl = &ctx->sock;
		
	/* Setup all sockets */
	for(i = 0; i < SOCK_NUM; i++) {
		port = SOCK_MIN_PORT + i;

		if((sockfd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0)
			goto err_close_socks;

		tbl->mask[i] = 0;
		tbl->fd[i] = sockfd;
		tbl->int_port[i] = port;
		tbl->ext_port[i] = port;
		tbl->tout[i] = 0;
		tbl->status[i] = 0;
		tbl->que[i] = NULL;

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
		if((network.flg & LCP_F_UPNP) != 0 ) {
			if(upnp_add(&ctx->upnp, port, port) != 0)
				goto err_close_socks;
		}
	}

	return 0;

err_close_socks:
	/* Close all opened sockets */
	for(; i >= 0; i--) {
		if((ctx->flg & LCP_F_UPNP) != 0)
			upnp_remv(&ctx->upnp, tbl->ext_port[i]);

		close(tbl->fd[i]);

		/* Reset the mask of the entry */
		tbl->mask[i] = 0;
	}

	return -1;
}


/* Close all sockets and clear the socket-table */
static void lcp_sock_close(struct lcp_ctx *ctx)
{
	int i;
	struct socket_table *tbl = &ctx->sock;

	for(i = 0; i < SOCK_NUM; i++) {
		if((ctx->flg & LCP_F_UPNP) != 0)
			upnp_remv(&ctx->upnp, tbl->ext_port[i]);

		close(tbl->fd[i]);

		/* Reset the mask of the entry */
		tbl->mask[i] = 0;
	}
	
}


LCP_API struct lcp_ctx *lcp_init(void)
{
	struct lcp_ctx *ctx;

	if(!(ctx = malloc(sizeof(struct lcp_ctx))))
		return -1;

	/* Discover the LCP_APIal address and test port preservation */
	if(lcp_discover(ctx) < 0)
		goto err_free_ctx;

	/* Discover the internal address */
	if(lcp_get_intern(ctx) < 0)
		goto err_free_ctx;

	/* Initialize the socket-table */
	if(lcp_sock_init(ctx) < 0)
		goto err_free_ctx;

	/* Initialize key-buffers */
	mpz_init(ctx->pvt.n); 
	mpz_init(ctx->pvt.e); 
	mpz_init(ctx->pvt.d); 
	mpz_init(ctx->pvt.p); 
	mpz_init(ctx->pvt.q);

	mpz_init(ctx->pub.n);
	mpz_init(ctx->pub.e);

	/* Initialize the keys */
	gen_keys(&ctx->pvt, &ctx->pub);
	return ctx;

err_free_ctx:
	free(ctx);
	return NULL;
}


LCP_API void lcp_close(struct lcp_ctx *ctx)
{
	if(!ctx)
		return;

	/* Free the keys */
	free_keys(&ctx->pvt, &ctx->pub);

	/* Close all sockets and clear the socket-table */
	lcp_sock_close(ctx);
}


LCP_API int lcp_get_slot(struct lcp_ctx *ctx)
{
	int i;

	for(i = 0; i < SOCK_NUM; i++) {
		if(ctx->sock.mask[i] == 0)
			return i;
	}

	return -1;
}


LCP_API int lcp_sendto(int fd, struct sockaddr_in6 *dst, char *buf, int len)
{
	struct sockaddr *addr = (struct sockaddr *)dst;
	int addr_sz = sizeof(struct sockaddr_in6);
	return sendto(fd, buf, len, 0, addr, addr_sz);
}


LCP_API int lcp_send(short slot, char *buf, int len)
{
	struct socket_table *tbl = &network.sock;
	int dst_sz = sizeof(struct sockaddr_in6);	
	struct sockaddr *addr;

	if(slot < 0 || slot >= SOCK_NUM)
		return -1;

	if(tbl->mask[slot] == 0)
		return -1;

	addr = (struct sockaddr *)&tbl->dst[slot];
	return sendto(tbl->fd[slot], buf, len, 0, addr, dst_sz);
}


LCP_API void lcp_update(void)
{
	int i, j;
	struct socket_table *tbl = &network.sock;
	time_t ti;
	char buf[512];
	struct sockaddr *addr;
	int sz = sizeof(struct sockaddr_in6);
	struct sock_pck_que *ptr; 

	time(&ti);

	for(i = 0; i < SOCK_NUM; i++) {
		if(tbl->mask[i] == 0)
			continue;

		addr = (struct sockaddr *)&tbl->dst[i];

		/* When port preservation is used */
		if((network.flg | LCP_F_PPR) != 0) {
			/* Send a keepalive-message */
			if(ti >= tbl->tout[i]) {
				buf[0] = 0;
				buf[1] = 0;

				sendto(tbl->fd[i], buf, 2, 0, addr, sz);
				tbl->tout[i] = ti + SOCK_PPR_TOUT; 
			}
		}
	
		ptr = tbl->que[i];
		while(ptr != NULL) {
			if(ti >= ptr->tout) {
				ptr->count++;
				ptr->tout = ti + SOCK_PCK_TOUT;

				if(ptr->count > 3) {
					/* Failed to send packet */
				}

				sendto(tbl->fd[i], ptr->buf, ptr->len, 0, 
						addr, sz);
			}

			ptr = ptr->next;		
		}
	}
}


LCP_API void lcp_print_sock(void)
{
	int i;
	struct socket_table *tbl = &network.sock;

	printf("NUM\tMASK\tFD\tINT_PORT\tEXT_PORT\tTOUT\n");
	for(i = 0; i < SOCK_NUM; i++) {
		printf("%d\t%d\t%d\t%d   \t%d   \t%lu\n", i,
				tbl->mask[i], tbl->fd[i], 
				tbl->int_port[i], tbl->ext_port[i], 
				tbl->tout[i]);
	}
	printf("\n");
}


LCP_API int lcp_btob_4to6(struct in_addr *src, struct in6_addr *dst)
{
	char *ptr = (char *)dst;
	memset(ptr, 0, sizeof(struct in6_addr));
	memset(ptr + 10, 0xff, 2);
	memcpy(ptr + 12, src, sizeof(struct in_addr));
	return 0;
}


LCP_API char *lcp_str_addr6(struct in6_addr *addr)
{
	static char buf[INET6_ADDRSTRLEN];
	if(inet_ntop(AF_INET6, addr, buf, INET6_ADDRSTRLEN) == NULL)
		return "failed";
	return buf;
}
