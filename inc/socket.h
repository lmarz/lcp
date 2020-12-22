#ifndef _LCP_SOCKET_H
#define _LCP_SOCKET_H

#include <stdint.h>
#ifdef __MINGW32__
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <poll.h>
#endif /* __MINGW32__ */

#include "define.h"

/* Connnection-flags */
#define LCP_CON_F_PROXY    (0<<0)
#define LCP_CON_F_DIRECT   (1<<0)

/* Network-flags */
#define LCP_NET_F_OPEN     (1<<2)
#define LCP_NET_F_PPR      (1<<3)
#define LCP_NET_F_UPNP     (1<<4)
#define LCP_NET_F_PMP      (1<<5)
#define LCP_NET_F_PCP      (1<<6)

#define LCP_SOCK_NUM         10
#define LCP_SOCK_MIN_PORT    25290
#define LCP_SOCK_PPR_TOUT    8
#define LCP_SOCK_PCK_TOUT    2

/* Socket-masks */
#define LCP_SOCK_M_NONE          0x00
#define LCP_SOCK_M_INIT          0x01

#define ADDR6_SIZE sizeof(struct sockaddr_in6)

struct lcp_sock_tbl {
	short num;
	short base;
	char flg;
	void *hdl;

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
 * Initialize the socket-table and bind the sockets. Also forward ports on the
 * NAT if possible using uPnP. If this function fails, it will clean up the
 * socket-table and remove the entries on the NAT. Note that the handle will be
 * attached to the socket-table and therefore mustn't be deleted or freed before
 * the socket table is closed.
 *
 * @tbl: Pointer to the socket-table
 * @flg: The network-flags indicating possible actions(ie uPnP)
 * @hdl: A handle used for certain actions(ie uPnP)
 * @base: The base port to start binding from, use -1 for default(25290)
 * @num: The number of sockets to bind, use -1 for default(10)
 *
 * Returns: 0 on success or -1 if an error occurred
 */
LCP_API int lcp_sock_init(struct lcp_sock_tbl *tbl, char flg, void *hdl, 
		short base, short num);


/*
 * Close the sockets table, unbind all sockets and remove forwarding-entries on
 * the NAT.
 *
 * @tbl: Pointer to the socket-table
 */
LCP_API void lcp_sock_close(struct lcp_sock_tbl *tbl);


/*
 * Get the slot of a socket with a specific port in the socket-table.
 *
 * @tbl: Pointer to the socket-table
 * @port: The port-number to search for
 *
 * Returns: The slot in the socket-table or -1 if an error occurred
 */
LCP_API short lcp_sock_sel_port(struct lcp_sock_tbl *tbl, short port);


/*
 * Get a slot in the socket-table to send messages with.
 *
 * @tbl: Pointer to the socket-table
 *
 * Returns: A slot in the table or -1 if an error occurred
 */
LCP_API int lcp_sock_get_open(struct lcp_sock_tbl *tbl, short *ptr, short num);


/*
 * Check if any of the sockets in the socket-table have received a packet. If
 * that is the case write the received packet to the buffer, set the length of
 * the packet and return 1. Note that this function will return the whole packet
 * including the header. Furthermore, this function is non-blocking.
 *
 * @tbl: Pointer to the socket-table
 * @buf: A buffer to write the received packet to
 * @max_len: The size of the buffer
 * @len: A pointer to write the length of the packet to
 * @addr: A pointer to write the address to the packet has been sent from
 * @slot: A pointer to write the socket-slot to
 * 
 * Returns: 1 if a packet has been received, 0 if no packet has been received
 * 	and -1 if an error occurred
 */
LCP_API int lcp_sock_recv(struct lcp_sock_tbl *tbl, char *buf, int max_len,
		int *len, struct sockaddr_in6 *addr, short *slot);


/*
 * Send a packet using on of the sockets in the socket-table.
 *
 * @tbl: A pointer to the socket-table
 * @slot: The slot the wanted socket is on
 * @dst: The destination-address to send the packet to
 * @buf: The buffer containing the whole packet including the header
 * @len: The length of the packet
 *
 * Returns: 0 on succcess or -1 if an error occurred
 */
LCP_API int lcp_sock_send(struct lcp_sock_tbl *tbl, short slot, 
		struct sockaddr_in6 *dst, char *buf, int len);


/*
 * Print a socket-table in the console.
 *
 * @tbl: Pointer to the socket-table
 */
LCP_API void lcp_sock_print(struct lcp_sock_tbl *tbl);

#endif
