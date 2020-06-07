#ifndef _LCP_H
#define _LCP_H

struct lcp_ctx;

#include "define.h"
#include "utils.h"
#include "rsa.h"
#include "header.h"
#include "socket.h"
#include "event.h"
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define LCP_PCK_MAX    504
#define LCP_BUF_MAX    496

/* An entry in the send-que, to verify the packet reached it's destination */
struct lcp_pck_que;
struct lcp_pck_que {
	struct lcp_pck_que *prev;
	struct lcp_pck_que *next;
	uint16_t id;

	char *buf;
	int len;

	char count;
	time_t tout;
};

struct lcp_con;
struct lcp_con {
	struct lcp_con *next;

	struct sockaddr_in6 addr;
	short slot;

	uint8_t flg;
	struct lcp_pck_que *que;

	char status;
	time_t tout;
	char count;

	struct lcp_pub_key pub;
	uint16_t proxy_id;
};

struct lcp_con_lst {
	struct lcp_con *tbl;
	short num;
};

/*
 * Define the IPv6-addresses and ports of the default servers.
 */
#define DISCO_IP       "::1"
#define DISCO_PORT     4243

#define PROXY_IP       "::1"
#define PROXY_PORT     4244 

struct lcp_ctx {
	struct in6_addr int_addr;
	struct in6_addr ext_addr;
	uint8_t flg;

	struct lcp_sock_tbl sock;
	struct lcp_upnp_hdl upnp;
	struct lcp_con_lst con;
	struct lcp_evt_ele *evt;

	struct sockaddr_in6 disco_addr;
	struct sockaddr_in6 proxy_addr;

	struct lcp_pvt_key pvt;
	struct lcp_pub_key pub;
};


/*
 * Gather all information about the NAT, the internal and LCP_APIal network. 
 * Then initialize the socket-table and setup the sockets. Also use uPnP to 
 * forward ports on the NAT if possible.
 *
 * Returns: 0 on success or -1 if an error occurred
 */
LCP_API struct lcp_ctx *lcp_init(short base, short num, char ovw, 
		struct sockaddr_in6 *disco, struct sockaddr_in6 *proxy);


/*
 * Close the socket table and close all open sockets. If uPnP is enabled also
 * remove entries from the NAT.
 */
LCP_API void lcp_close(struct lcp_ctx *ctx);


/*
 * Get an unused slot in the socket-table to open a new connection on.
 *
 * Returns: An unused slot or -1 if an error occurred
 */
LCP_API int lcp_get_slot(struct lcp_ctx *ctx);


/*
 * Connect to a different maschine and establish a connection.
 *
 * @dst: The address of the other maschine to connect to
 * @flg: Options on how to establish the connection
 *
 * Returns: Either a slot in the socket-table or -1 if an error occurred
 */
LCP_API struct lcp_con *lcp_connect(struct lcp_ctx *ctx, short port, 
		struct sockaddr_in6 *dst, uint8_t flg);


/*
 * Close a connection and reset the socket.
 *
 * @slot: The slot in the socket-table
 */
LCP_API int lcp_disconnect(struct lcp_ctx *ctx, struct sockaddr_in6 *addr);


/*
 * Update all sockets in the socket-table and send keep-alive messages if
 * necessary. Also process incomming packages.
 */
LCP_API void lcp_update(struct lcp_ctx *ctx);


/*
 * Send a packet to the given destination and verify that it reached it's
 * destination. If the transmission failed, this function will retry sending
 * the packet to the destination two more times. If that failed, an error-evt
 * will be pushed into the event-queue.
 *
 * @slot: The socket-slot to use (has to be connected already)
 * @buf: The buffer to send to the other maschine
 * @len: The length of the buffer
 *
 * Returns: 0 on success or -1 if an error occurred
 */
LCP_API int lcp_send(struct lcp_ctx *ctx, struct sockaddr_in6 *addr, 
		char *buf, int len);


/*
 * 
 */
LCP_API int lcp_hint(struct lcp_ctx *ctx, uint16_t flg);

/*
 * 
 */
LCP_API void lcp_con_close(struct lcp_ctx *ctx);


/*
 * 
 */
LCP_API struct lcp_con *lcp_con_add(struct lcp_ctx *ctx,
		struct sockaddr_in6 *dst, short slot, uint8_t flg);


/*
 * 
 */
LCP_API void lcp_con_remv(struct lcp_ctx *ctx, struct sockaddr_in6 *addr);


/*
 * 
 */
LCP_API void lcp_con_update(struct lcp_ctx *ctx);


/*
 * 
 */
LCP_API int lcp_con_send(struct lcp_ctx *ctx, struct lcp_con *con, char *buf, 
		int len);


/*
 * 
 */
LCP_API struct lcp_con *lcp_con_sel_addr(struct lcp_ctx *ctx, 
		struct sockaddr_in6 *addr);


LCP_API struct lcp_con *lcp_con_sel(struct lcp_ctx *ctx, 
		struct sockaddr_in6 *addr, short slot);


/*
 * 
 */
LCP_API void lcp_con_print(struct lcp_ctx *ctx);


/*
 * 
 */
LCP_API int lcp_que_add(struct lcp_con *con, char *buf, int len, uint16_t id);


/*
 * 
 */
LCP_API struct lcp_pck_que *lcp_que_sel(struct lcp_con *con, uint16_t id);

#endif
