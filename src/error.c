#include "error.h"
#include <stdio.h>
#include <stdlib.h>

/* Redefine global error-code */
char lcp_errno = 0;

extern const char *lcp_strerr(enum lcp_err_id id) {
#define LCP_ERR_TEXT(id, text) text,
	static const char *table[] = {
		LCP_ERR_TABLE(LCP_ERR_TEXT)
	};
#undef LCP_ERR_TEXT

	if(id < 0 || id >= kNumErrs)
		return "*House is burning* - This is fine!";

	return table[id];
}

