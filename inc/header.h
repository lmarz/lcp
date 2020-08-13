#ifndef _LCP_HEADER_H
#define _LCP_HEADER_H

#include <stdint.h>

/* Size of the header in bytes */
#define LCP_HDR_SIZE          4
#define LCP_PROXY_HDR_SIZE    4


/* Define the control-bits */
#define LCP_C_INI (1<<0)
#define LCP_C_ACK (1<<1)
#define LCP_C_RST (1<<2)
#define LCP_C_HNT (1<<3)
#define LCP_C_PSH (1<<4)
#define LCP_C_FIN (1<<5)
#define LCP_C_KAL (1<<6)

/* Define the flag-bits */
#define LCP_F_ENC      0x02

struct lcp_hdr {
	uint16_t id;

	/* Control-bits */
	uint8_t cb;
		
	/* Packet-flags */
	uint8_t flg;
} __attribute__((__packed__));

#endif
