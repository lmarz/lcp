#include "event.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

LCP_API int lcp_push_evt(struct lcp_ctx *ctx, unsigned char type, 
		short slot, struct sockaddr_in6 *addr, char *buf, int len)
{
	struct lcp_evt_ele *evt;

	if(!(evt = malloc(sizeof(struct lcp_evt_ele))))
		return -1;

	evt->next = NULL;
	evt->evt.type = type;
	evt->evt.slot = slot;
	
	if(addr != NULL)
		evt->evt.addr = *addr;

	if(buf != NULL && len > 0) {
		if(!(evt->evt.buf = malloc(len))) {
			free(evt);
			return -1;
		}

		memcpy(evt->evt.buf, buf, len);
		evt->evt.len = len;
	}
	else {
		evt->evt.buf = NULL;
		evt->evt.len = 0;
	}


	if(ctx->evt == NULL) {
		ctx->evt = evt;
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
