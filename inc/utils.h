#ifndef _LCP_UTILS_H
#define _LCP_UTILS_H

#include "define.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

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
 * @af: The address-family to use(AF_INET, AF_INET6)
 * @addr: Pointer to the address
 *
 * Returns: A string containing the address in text form
 */
LCP_API char *lcp_str_addr(int af, struct in6_addr *addr);

#endif
