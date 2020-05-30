#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

LCP_API int lcp_btob_4to6(struct in_addr *src, struct in6_addr *dst)
{
	char *ptr = (char *)dst;
	memset(ptr, 0, sizeof(struct in6_addr));
	memset(ptr + 10, 0xff, 2);
	memcpy(ptr + 12, src, sizeof(struct in_addr));
	return 0;
}


LCP_API char *lcp_str_addr(int af, struct in6_addr *addr)
{
	static char buf[INET6_ADDRSTRLEN];
	if(inet_ntop(af, addr, buf, INET6_ADDRSTRLEN) == NULL)
		return "failed";
	return buf;
}
