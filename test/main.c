#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lcp.h"

int main(void)
{
	struct lcp_ctx *ctx;

	if(!(ctx = lcp_init(LCP_CLIENT))) {
		printf("Failed to initialize lcp-context\n");
		return -1;
	}

	lcp_close(ctx);
	return 0;
}
