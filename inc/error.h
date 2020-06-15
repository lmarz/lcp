#ifndef _LCP_ERROR_H
#define _LCP_ERROR_H

/* =====================================================
 *                                                      
 * IMPORTANT:
 * NEVER EVEN THINK ABOUT FORMATING THIS FILE!!!!
 * ...or do whatever, im just a header
 *                                                       
 * ===================================================== */

#include "define.h"

/* The global error-code */
LCP_GLOBAL char lcp_errno;

/* The error-messages */
#define LCP_ERR_TABLE(V)                                                       \
  V(LCP_ENONE,      "Success")                                                 \
  V(LCP_ESOUPNP,    "Failed to forward port using uPnP")

#define LCP_ERR_ID(id, text) id,
enum lcp_err_id {
  LCP_ERR_TABLE(LCP_ERR_ID)
  kNumErrs
};
#undef LCP_ERR_ID

/* Get the error-message assigned to the error-code */
extern const char *lcp_strerr(enum lcp_err_id id);

#endif
