#ifndef _LCP_HEADER_H
#define _LCP_HEADER_H

#include <stdint.h>

/* Size of the header in bytes */
#define LCP_HDR_LEN    4

/* Define the control-bits */
#define LCP_C_INI      0x01
#define LCP_C_ACK      0x02
#define LCP_C_RST      0x04
#define LCP_C_HNT      0x08
#define LCP_C_PSH      0x10
#define LCP_C_FIN      0x20

/* Define the flag-bits */
#define LCP_F_ENC      0x01

struct lcp_hdr {
	uint16_t id;

	/* Control-bits */
	uint8_t cb;
		
	/* Packet-flags */
	uint8_t flg;
} __attribute__((__packed__));

#endif
