#ifndef _LCP_UPNP_H
#define _LCP_UPNP_H

#include "define.h"
#include "miniupnpc/miniupnpc.h"
#include "miniupnpc/upnpcommands.h"


struct lcp_upnp_hdl {
	struct UPNPUrls urls;
	struct IGDdatas data;
	struct UPNPDev *dev;
	char addr[64];
};


/*
 * Disover all uPnP devices and find a valid IGD. Then attach necessary data
 * to the context.
 *
 * @hdl: Pointer to the uPnP-handle
 *
 * Returns: 0 on success or -1 if an error occurred
 */
LCP_API int lcp_upnp_prep(struct lcp_upnp_hdl *hdl);


/*
 * Free the necessary data and detach it from the context. 
 *
 * @hdl: Pointer to the uPnP-handle
 */
LCP_API void lcp_upnp_close(struct lcp_upnp_hdl *hdl);


/*
 * Add a new forward-entry in the NAT-table.
 *
 * @hdl: Pointer to the uPnP-handle
 * @in: The internal port
 * @ex: The LCP_APIal port
 *
 * Returns: 0 on success or -1 if an error occurred
 */
LCP_API int lcp_upnp_add(struct lcp_upnp_hdl *hdl, unsigned short in,
		unsigned int ex);


/*
 * Remove a forward-entry from the NAT-table.
 *
 * @hdl: Pointer to the uPnP-handle
 * @ex: The LCP_APIal port to free
 */
LCP_API void lcp_upnp_remv(struct lcp_upnp_hdl *hdl, unsigned short ex);

#endif
