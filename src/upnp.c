#include "upnp.h"

#include <stdio.h>
#include <string.h>

LCP_API int lcp_upnp_prep(struct lcp_upnp_hdl *hdl)
{
	struct UPNPUrls urls;
	struct IGDdatas data;
	struct UPNPDev *dev = NULL;
	char addr[64];

	if(!hdl)
		return -1;

	/* Discover all uPnP devices */
	if(!(dev = upnpDiscover(2000, NULL, NULL, 0, 0, 2, NULL)))
		goto err_free_dev;

	/* Retrieve a valid Internet Gateway Device */
	if((UPNP_GetValidIGD(dev, &urls, &data, addr, 64)) != 1)
		goto err_free_urls;

	hdl->urls = urls;
	hdl->data = data;
	hdl->dev = dev;
	strcpy(hdl->addr, addr);
	return 0;

err_free_urls:
	FreeUPNPUrls(&urls);

err_free_dev:
	freeUPNPDevlist(dev);
	return -1;
}


LCP_API void lcp_upnp_close(struct lcp_upnp_hdl *hdl)
{
	if(!hdl)
		return;

	FreeUPNPUrls(&hdl->urls);
	freeUPNPDevlist(hdl->dev);
}


LCP_API int lcp_upnp_add(struct lcp_upnp_hdl *hdl, unsigned short in,
		unsigned int ex)
{	
	char int_port_str[6];
	char ext_port_str[6];

	sprintf(int_port_str, "%d", in);
	sprintf(ext_port_str, "%d", ex);

	return UPNP_AddPortMapping(
			hdl->urls.controlURL, 
			hdl->data.first.servicetype,
			ext_port_str,
			int_port_str,
			hdl->addr, 
			"LCP", 
			"UDP",
			0,
			"0"
			);
}


LCP_API void lcp_upnp_remv(struct lcp_upnp_hdl *hdl, unsigned short ex)
{
	char ext_port_str[6];

	sprintf(ext_port_str, "%d", ex);

	UPNP_DeletePortMapping(hdl->urls.controlURL, 
			hdl->data.first.servicetype,
			ext_port_str, "UDP", 0);
}
