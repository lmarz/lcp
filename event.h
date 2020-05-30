#ifndef _LCP_EVENT_H
#define _LCP_EVENT_H

#include "define.h"
#include "lcp.h"
#include <arpa/inet.h>
#include <netinet/in.h>


#define LCP_CONNECTED      0x01
#define LCP_DISCONNECTED   0x02
#define LCP_RECEIVED       0x03
#define LCP_TIMEDOUT       0x04
/*
 * 
 */
struct lcp_evt {
	unsigned char type;

	short slot;
	struct sockaddr_in6 addr;

	char *buf;
	int len;
};

struct lcp_evt_ele;
struct lcp_evt_ele {
	struct lcp_evt_ele *next;
	struct lcp_evt evt;
};

/*
 * Push a new event into the event-list.
 *
 * @ctx: Pointer to the context-struct
 * @type: The type of the event
 * @slot: The slot in the socket-table
 * @addr: Pointer to the address
 * @buf: A buffer containing the necessary data
 * @len: The length of the buffer
 */
LCP_API int lcp_push_evt(struct lcp_ctx *ctx, unsigned char type, 
		short slot, struct sockaddr_in6 *addr, char *buf, int len);

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

#endif
