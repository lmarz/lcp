#ifndef _LCP_H
#define _LCP_H

struct lcp_ctx;

#include "define.h"
#include "error.h"
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

	char con_flg;
	
	uint8_t ini_pck_flg;
	uint8_t pck_flg;
	struct lcp_pck_que *que;

	char status;
	time_t tout;
	char count;

	time_t last_kalive;
	time_t kalive;

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
#define LCP_DISCO_IP       "::1"
#define LCP_DISCO_PORT     4243

#define LCP_PROXY_IP       "::1"
#define LCP_PROXY_PORT     4244 

struct lcp_ctx {
	struct in6_addr int_addr;
	struct in6_addr ext_addr;
	uint8_t net_flg;
	char con_flg;

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
 * Create and initialize a new LCP-context, which is used for further action.
 *
 * @base: The base-port-number which will be used(use -1 for default)
 * @num: The number of sockets(use -1 for default)
 * @ovw: The flag overwrite, if active the discovery progress will be skipped
 * @disco: The IPv6-address of the discovery-server
 * @proxy: The IPv6-address of the proxy-server
 *
 * Returns: A pointer to the created context or NULL if an error occurred
 */
LCP_API struct lcp_ctx *lcp_init(short base, short num, char ovw, 
		struct sockaddr_in6 *disco, struct sockaddr_in6 *proxy);


/*
 * Close the LCP-context, close all sockets and free the allocated memory.
 *
 * @ctx: Pointer to the context
 */
LCP_API void lcp_close(struct lcp_ctx *ctx);


/*
 * Get an open socket-slot in the socket-table to open a new connection with.
 *
 * @ctx: Pointer to the context
 *
 * Returns: An open socket-slot or -1 if an error occurred
 */
LCP_API short lcp_get_slot(struct lcp_ctx *ctx);


/*
 * Connect to a different maschine and establish a connection. Note that this
 * function will only initate a new connection, but to actually establish the
 * full connection, the framework has to be updated regularly. If necessary, the
 * function will first contact the proxy to join a link, so later packages could
 * be relayed over the proxy.
 *
 * @ctx: Pointer to the context
 * @port: The port to open the connection on (Big-Endian)
 * @addr: The destination-address to connect to
 * @con_flg: Flags indicating the type of connection, ie proxy(0) or direct(1)
 * @pck_flg: Flags for the packets, ie encryption
 *
 * Returns: A pointer to the new connection-struct or NULL if an error occurred
 */
LCP_API struct lcp_con *lcp_connect(struct lcp_ctx *ctx, short slot, 
		struct sockaddr_in6 *addr, char con_flg, uint8_t pck_flg);


/*
 * Close a connection and free allocated memory. If necessary also reset the
 * socket.
 *
 * @ctx: Pointer to the context
 * @addr: The address of the connection to close
 *
 * Returns: 0 on success or -1 if an error occurred 
 */
LCP_API int lcp_disconnect(struct lcp_ctx *ctx, struct sockaddr_in6 *addr);


/*
 * Update all sockets in the socket-table and send keep-alive messages if
 * necessary. Also process incomming packages and send out packets.
 *
 * @ctx: Pointer to the context
 */
LCP_API void lcp_update(struct lcp_ctx *ctx);


/*
 * Send a packet to the given destination and verify that it reached it's
 * destination. If the transmission failed, this function will retry sending
 * the packet to the destination two more times. If that failed, an error-event
 * will be pushed into the event-queue. Note that to send a packet, a connection
 * has already been established.
 *
 * @ctx: Pointer to the context
 * @addr: The address of the connection
 * @buf: The buffer to send to the other maschine
 * @len: The length of the buffer
 *
 * Returns: 0 on success or -1 if an error occurred
 */
LCP_API int lcp_send(struct lcp_ctx *ctx, struct sockaddr_in6 *addr, 
		char *buf, int len);


/*
 * Send a packet to the given destination, considering that a connection has to
 * be established already. This function also requires an op-code which will
 * then be inserted into the header, but will not encrypt the message. Therefore
 * this function will be primary used to send custom RST- and ACK-packets.
 *
 * @ctx: Pointer to the context
 * @addr: The address of the connection
 * @op: The op-code to insert into the header
 * @buf: The buffer to attach to the packet
 * @len: The length of the buffer
 *
 * Returns: 0 on success or -1 if an error occurred
 */
LCP_API int lcp_sendto(struct lcp_ctx *ctx, struct sockaddr_in6 *addr,
		uint8_t op, char *buf, int len);


/*
 * Synchronize the connection-flags with the other side. Note that if the
 * connection has not been initialized with encryption enabled, you can't
 * enable encryption, but have to create a new connection.
 *
 * @con: Pointer to the connection
 * @pck_flg: The new packet-flags for the connection
 *
 * Returns: 0 on success or -1 if an error occurred
 */
LCP_API int lcp_hint(struct lcp_con *con, uint8_t pck_flg);


/*
 * Close all connection attached to a context and clear the connection-table.
 *
 * @ctx: Pointer to the context
 */
LCP_API void lcp_con_close(struct lcp_ctx *ctx);


/*
 * Add a new connection to the connection-list.
 *
 * @ctx: Pointer to the context
 * @slot: The socket-slot to open the connection with
 * @addr: The address of the connection
 * @con_flg: Flags indicating the type of connection, ie direct or proxy
 * @pck_flg: Flags for the package, ie encryption
 *
 * Returns: Pointer to the connection or NULL if an error occurred
 */
LCP_API struct lcp_con *lcp_con_add(struct lcp_ctx *ctx, short slot, 
		struct sockaddr_in6 *addr, char con_flg, uint8_t pck_flg);


/*
 * Remove a connection from the connection-list. 
 *
 * @ctx: Pointer to the context
 * @addr: The IPv6-address of the connection
 */
LCP_API void lcp_con_remv(struct lcp_ctx *ctx, struct sockaddr_in6 *addr);


/*
 * Update all the connections in the connection-list.
 *
 * @ctx: Pointer to the context
 */
LCP_API void lcp_con_update(struct lcp_ctx *ctx);


/*
 * Send a packet using a connection from the connection-list. This function will
 * relay the packet over a proxy. Note that this function requires the buffer
 * to already contain the header, but not the proxy-header which will be added
 * if necessary.
 *
 * @ctx: Pointer to the context
 * @con: Pointer to the connection
 * @buf: The buffer to send
 * @len: The length of the buffer in bytes
 *
 * Returns: The number of bytes send or -1 if an error occurred
 */
LCP_API int lcp_con_send(struct lcp_ctx *ctx, struct lcp_con *con, char *buf, 
		int len);


/*
 * Select a connection from the connection-list using the IPv6-address.
 *
 * @ctx: Pointer to the context
 * @addr: The address to search for
 *
 * Returns: Pointer to the connecion or NULL if an error occurred or if the
 * 	connection could not be found
 */
LCP_API struct lcp_con *lcp_con_sel_addr(struct lcp_ctx *ctx, 
		struct sockaddr_in6 *addr);


/*
 * Select a connection from the connection-list using the proxy-id if the
 * connection is relayed over a proxy.
 *
 * @ctx: Pointer to the context
 * @id: The proxy-id to search for
 *
 * Returns: pointer to the connection or NULL if an error occurred or if the
 * 	connection could not be found
 */
LCP_API struct lcp_con *lcp_con_sel_proxy(struct lcp_ctx *ctx, uint16_t id);


/*
 * Display all connection in the console.
 *
 * @ctx: Pointer to the context
 */
LCP_API void lcp_con_print(struct lcp_ctx *ctx);


/*
 * Add a new package to the package-queue of a connection. After pusing the
 * package into the que, the framework will try to send the package for 3 times
 * and relay it over a proxy if necessary. Note that the buffer already has to
 * contain the packet-header and proxy-header if required. 
 *
 * @con: Pointer to the connection
 * @buf: The buffer to send
 * @len: The length of the buffer in bytes
 * @id: The id of the package
 *
 * Returns: 0 on success or -1 if an error occurred
 */
LCP_API int lcp_que_add(struct lcp_con *con, char *buf, int len, uint16_t id);


/*
 * Remove a package from the package-queue.
 *
 * @con: Pointer to the connection
 * @ele: Pointer to the package-entry
 */
LCP_API void lcp_que_remv(struct lcp_con *con, struct lcp_pck_que *ele);


/*
 * Select a package from the package-queue by searching for the package-id.
 *
 * @con: Pointer to the connection
 * @id: The id of the package
 *
 * Returns: Either a pointer to the package-entry or NULL if an error occurred
 * 	or if the package could not be found
 */
LCP_API struct lcp_pck_que *lcp_que_sel(struct lcp_con *con, uint16_t id);

#endif
