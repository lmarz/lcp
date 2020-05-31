#ifndef _LCP_SOCKET_H
#define _LCP_SOCKET_H

#include "define.h"
#include "upnp.h"
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>

#define LCP_F_OPEN     0x04
#define LCP_F_PPR      0x08
#define LCP_F_UPNP     0x10
#define LCP_F_PMP      0x20
#define LCP_F_PCP      0x40

#define LCP_SOCK_NUM         10
#define LCP_SOCK_MIN_PORT    25290
#define LCP_SOCK_PPR_TOUT    8
#define LCP_SOCK_PCK_TOUT    2

#define LCP_SOCK_M_NONE          0x00
#define LCP_SOCK_M_INIT          0x01
#define LCP_SOCK_M_KEEPALIVE     0x02

struct lcp_sock_tbl {
	short num;
	short base;

	char               mask[LCP_SOCK_NUM];
	int                fd[LCP_SOCK_NUM];
	int                con_c[LCP_SOCK_NUM];
		
	unsigned short     int_port[LCP_SOCK_NUM];
	unsigned short     ext_port[LCP_SOCK_NUM];

	struct             sockaddr_in6 dst[LCP_SOCK_NUM];
	time_t             tout[LCP_SOCK_NUM];

	uint8_t            status[LCP_SOCK_NUM];

	struct pollfd      pfds[LCP_SOCK_NUM];
};

/*
 * 
 */
LCP_API int lcp_sock_init(struct lcp_sock_tbl *tbl, char flg, 
		struct lcp_upnp_hdl *upnp, short base, short num);


/*
 * 
 */
LCP_API void lcp_sock_close(struct lcp_sock_tbl *tbl, char flg,
		struct lcp_upnp_hdl *upnp);


/*
 * 
 */
LCP_API void lcp_sock_update(struct lcp_sock_tbl *tbl, char flg,
		struct lcp_upnp_hdl *upnp);


/*
 * Get the slot of a socket with a specific port in the socket-table.
 *
 * @tbl: Pointer to the socket-table
 * @port: The port-number to search for
 *
 * Returns: Either the slot in the socket-table or -1 if an error occurred
 */
LCP_API short lcp_sel_port(struct lcp_sock_tbl *tbl, short port);


/*
 * Get an unused and open slot in the socket-table.
 *
 * @tbl: Pointer to the socket-table
 *
 * Returns: Either a slot in the table or -1 if an error occurred
 */
LCP_API int lcp_sock_get_open(struct lcp_sock_tbl *tbl, char flg, short *ptr, 
		short num);


/*
 * 
 */
LCP_API int lcp_recv(struct lcp_sock_tbl *tbl, char *buf, int max_len,
		int *len, struct sockaddr_in6 *addr, short *slot);


/*
 * 
 */
LCP_API int lcp_sock_send(struct lcp_sock_tbl *tbl, short slot, 
		struct sockaddr_in6 *dst, char *buf, int len);


/*
 * 
 */
LCP_API void lcp_print_sock(struct lcp_sock_tbl *tbl);

#endif
