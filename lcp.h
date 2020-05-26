#ifndef _LCP_H
#define _LCP_H

#include "define.h"
#include "rsa.h"
#include "upnp.h"
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <gmp.h>

/*
 * 
 */
struct lcp_evt {
	unsigned char type;

	short slot;
	struct sockaddr_in6 addr;

	unsigned int id;

	char *buf;
	int len;
};

struct lcp_evt_ele;
struct lcp_evt_ele {
	struct lcp_evt_ele *next;
	struct lcp_evt evt;
};


/* An entry in the send-que, to verify the packet reached it's destination */
struct sock_pck_que {
	struct lcp_pck_que *next;

	char *buf;
	int len;

	char count;
	time_t tout;
};


#define LCP_SOCK_NUM         11
#define LCP_SOCK_MIN_PORT    25270
#define LCP_SOCK_PPR_TOUT    8
#define LCP_SOCK_PCK_TOUT    2

#define LCP_SOCK_M_NONE      0x00
#define LCP_SOCK_M_INUSE     0x01

struct lcp_sock_tbl {	
	unsigned short     mask[LCP_SOCK_NUM];
	int                fd[LCP_SOCK_NUM];

	unsigned short     int_port[LCP_SOCK_NUM];
	unsigned short     ext_port[LCP_SOCK_NUM];

	struct             sockaddr_in6 dst[LCP_SOCK_NUM];
	uint32_t           id[LCP_SOCK_NUM];

	time_t             tout[LCP_SOCK_NUM];

	uint8_t            status[LCP_SOCK_NUM];
	struct             sock_pck_que *que[LCP_SOCK_NUM];
};

#define LCP_HDR_LEN    8
#define LCP_PCK_MAX    504
#define LCP_BUF_MAX    496

/* Define the control-bits */
#define LCP_F_INI      0x01
#define LCP_F_ACK      0x02
#define LCP_F_RST      0x04
#define LCP_F_RSE      0x08
#define LCP_F_PSH      0x10
#define LCP_F_FIN      0x20

/* Define the flag-bits */
#define LCP_O_ENC      0x01

struct lcp_hdr {
	uint16_t id;

	/* Control-bits */
	uint32_t
		ini: 1,
		ack: 1,
		rst: 1,
		psh: 1,
		fin: 1,
		pad0: 3;
		
	/* Transmission-flags */
	uint32_t
		enc: 1,
		pad: 7;
} __attribute__((__packed__));

#define LCP_F_PPR      0x04
#define LCP_F_UPNP     0x08
#define LCP_F_PMP      0x10
#define LCP_F_PCP      0x20

/*
 * Define the IPv6-addresses and ports of the default servers.
 */
#define DISCO_IP       "::1"
#define DISCO_PORT     4243

#define PROXY_IP       "::1"
#define PROXY_PORT     4244 

struct lcp_ctx {
	struct lcp_sock_tbl sock;

	struct in6_addr int_addr;
	struct in6_addr ext_addr;
	uint8_t flg;

	struct sockaddr_in6 disco_addr;
	struct sockaddr_in6 proxy_addr;

	struct upnp_handle upnp;

	struct lcp_evt_ele *evt;

	struct pvt_key pvt;
	struct pub_key pub;
};



/*
 * Pull an event from the event-list and copy it to the given pointer.
 *
 * @ctx: Pointer to the lcp-context
 * @evt: An address to write the event to
 *
 * Returns: 1 if an event has been returned, 0 if there're no more events and
 * 	-1 if an error occurred
 */
LCP_API int lcp_pull_evt(struct lcp_ctx *ctx, struct lcp_evt *evt);


/*
 * Delete an event and free the memory attached to the event. This function has
 * the single purpose of preventing memory-leaks.
 *
 * @evt: Pointer to the event to delete
 */
LCP_API void lcp_del_evt(struct lcp_evt *evt);

/*
 * Gather all information about the NAT, the internal and LCP_APIal network. 
 * Then initialize the socket-table and setup the sockets. Also use uPnP to 
 * forward ports on the NAT if possible.
 *
 * Returns: 0 on success or -1 if an error occurred
 */
LCP_API struct lcp_ctx *lcp_init(void);


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
LCP_API int lcp_get_slot(void);


#define LCP_USEANY     -1
#define LCP_USENEW     -2

/*
 * Send a packet to the given destination. This function will use a given slot,
 * use a new slot or create a new socket to send the message, depending on the
 * value passed in slot. Sending packets using this function is not safe, as
 * this function will not check if the packet reached it's destination. To have
 * a safe option, use lcp_send() instead.
 *
 * @fd: The socket-descriptor
 * @dst: The destination to send the packet to
 * @buf: The buffer to send
 * @len: The length of the buffer in bytes
 *
 * Returns: 0 on success or -1 if an error occurred
 */
LCP_API int lcp_sendto(int fd, struct sockaddr_in6 *dst, char *buf, int len);


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
LCP_API int lcp_send(short slot, char *buf, int len);


/*
 * Connect to a different maschine and establish a connection.
 *
 * @dst: The address of the other maschine to connect to
 * @flg: Options on how to establish the connection
 *
 * Returns: Either a slot in the socket-table or -1 if an error occurred
 */
LCP_API short lcp_connect(struct sockaddr_in6 *dst, uint8_t flg);


/*
 * Close a connection and reset the socket.
 *
 * @slot: The slot in the socket-table
 */
LCP_API void lcp_disconnect(short slot);


/*
 * Update all sockets in the socket-table and send keep-alive messages if
 * necessary. Also process incomming packages.
 */
LCP_API void lcp_update(void);


/*
 * Show the socket-table in the console. 
 */
LCP_API void lcp_print_sock(void);


/*
 * Convert a binary IPv4-address to a binary IPv6-address.
 *
 * @src: The IPv4-address to convert
 * @dst: The IPv6-address to convert
 *
 * Returns: 0 on success or -1 if an error occurred
 */
LCP_API int lcp_btob_4to6(struct in_addr *src, struct in6_addr *dst);


/*
 * Convert an IPv6-address to a string.
 * IMPORTANT: This function is not thread-safe!
 *
 * @addr: Pointer to the address
 *
 * Returns: A string containing the address in text form
 */
LCP_API char *lcp_str_addr6(struct in6_addr *addr);


/*
 *  
 */
LCP_API int lcp_req_token(char *uname, char *pswd);


/*
 * 
 */
LCP_API int lcp_req_peers(void);

#endif
