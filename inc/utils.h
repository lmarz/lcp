#ifndef _LCP_UTILS_H
#define _LCP_UTILS_H

#ifdef __MINGW32__
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif /* __MINGW32__ */

#include "define.h"

/*
 * Set a address-struct in a standardized way.
 *
 * @addr: The address-struct to initialize
 * @ip: Pointer to the address of the IPv6-address
 * @port: Pointer to address of the port in the Big-Endian-Format
 */
LCP_API void lcp_addr(struct sockaddr_in6 *addr, void *ip, void *port);


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
 * @ip: Pointer to a buffer containing the address
 *
 * Returns: A string containing the address in text form
 */
LCP_API char *lcp_str_ip(int af, void *ip);


/*
 * 
 */
LCP_API char *lcp_str_addr6(struct sockaddr_in6 *addr);

#endif
