#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


LCP_API void lcp_addr(struct sockaddr_in6 *addr, void *ip, void *port)
{
	memset(addr, 0, sizeof(struct sockaddr_in6));
	addr->sin6_family = AF_INET6;
	memcpy(&addr->sin6_port, port, 2);
	memcpy(&addr->sin6_addr, ip, sizeof(struct in6_addr));
}


LCP_API int lcp_btob_4to6(struct in_addr *src, struct in6_addr *dst)
{
	char *ptr = (char *)dst;
	memset(ptr, 0, sizeof(struct in6_addr));
	memset(ptr + 10, 0xff, 2);
	memcpy(ptr + 12, src, sizeof(struct in_addr));
	return 0;
}


LCP_API char *lcp_str_ip(int af, void *ip)
{
	static char buf[64];
	int len = af == AF_INET6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN;
	if(inet_ntop(af, ip, buf, len) == NULL)
		return "failed";
	return buf;
}

LCP_API char *lcp_str_addr6(struct sockaddr_in6 *addr)
{
	static char buf[128];

	sprintf(buf, "%s:%d", lcp_str_ip(AF_INET6, &addr->sin6_addr),
			ntohs(addr->sin6_port));

	return buf;
}
