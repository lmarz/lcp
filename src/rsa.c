#include "rsa.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

LCP_API void lcp_init_pvt(struct lcp_pvt_key *pvt)
{
	mpz_init(pvt->n); 
	mpz_init(pvt->e); 
	mpz_init(pvt->d); 
	mpz_init(pvt->p); 
	mpz_init(pvt->q);
}


LCP_API void lcp_init_pub(struct lcp_pub_key *pub)
{
	mpz_init(pub->n);
	mpz_init(pub->e);
}


LCP_API void lcp_clear_pvt(struct lcp_pvt_key *pvt)
{
	mpz_clear(pvt->n); 
	mpz_clear(pvt->e); 
	mpz_clear(pvt->d); 
	mpz_clear(pvt->p); 
	mpz_clear(pvt->q);	
}


LCP_API void lcp_clear_pub(struct lcp_pub_key *pub)
{
	mpz_clear(pub->n);
	mpz_clear(pub->e);
}

LCP_API void lcp_gen_keys(struct lcp_pvt_key *pvt, struct lcp_pub_key *pub)
{
	char buf[LCP_BUFFER_SIZE];
	int i;
	mpz_t phi;
	mpz_t tmp1;
	mpz_t tmp2; 

	mpz_init(phi);
	mpz_init(tmp1);
	mpz_init(tmp2);

	srand(time(NULL));

	mpz_set_ui(pvt->e, 3); 

	for(i = 0; i < LCP_BUFFER_SIZE; i++)
		buf[i] = rand() % 0xFF;

	buf[0] |= 0xC0;

	buf[LCP_BUFFER_SIZE - 1] |= 0x01;

	mpz_import(tmp1, LCP_BUFFER_SIZE, 1, sizeof(char), 0, 0, buf);

	mpz_nextprime(pvt->p, tmp1);

	mpz_mod(tmp2, pvt->p, pvt->e);
	while(!mpz_cmp_ui(tmp2, 1)) {
		mpz_nextprime(pvt->p, pvt->p);
		mpz_mod(tmp2, pvt->p, pvt->e);
	}

	do {
		for(i = 0; i < LCP_BUFFER_SIZE; i++)
			buf[i] = rand() % 0xFF;

		buf[0] |= 0xC0;
		buf[LCP_BUFFER_SIZE - 1] |= 0x01;
		mpz_import(tmp1, LCP_BUFFER_SIZE, 1, sizeof(char), 0, 0, buf);
		mpz_nextprime(pvt->q, tmp1);
		mpz_mod(tmp2, pvt->q, pvt->e);
		while(!mpz_cmp_ui(tmp2, 1)) {
			mpz_nextprime(pvt->q, pvt->q);
			mpz_mod(tmp2, pvt->q, pvt->e);
		}
	} while(mpz_cmp(pvt->p, pvt->q) == 0);

	mpz_mul(pvt->n, pvt->p, pvt->q);

	mpz_sub_ui(tmp1, pvt->p, 1);
	mpz_sub_ui(tmp2, pvt->q, 1);
	mpz_mul(phi, tmp1, tmp2);

	if(mpz_invert(pvt->d, pvt->e, phi) == 0) {
		mpz_gcd(tmp1, pvt->e, phi);
		printf("gcd(e, phi) = [%s]\n", mpz_get_str(NULL, 16, tmp1));
		printf("Invert failed\n");
	}

	mpz_set(pub->e, pvt->e);
	mpz_set(pub->n, pvt->n);

	mpz_clear(phi);
	mpz_clear(tmp1);
	mpz_clear(tmp2);
}


LCP_API int lcp_encrypt(char **out, int *out_len, char *in, int in_len, 
		struct lcp_pub_key pub)
{
	char *ret;
	char block[LCP_BLOCK_SIZE];
	mpz_t m;
	mpz_t c;

	int i = 0;
	int left = in_len;
	int num = (int)ceil((double)in_len / LCP_BUF_SIZE);
	int size = num * LCP_BLOCK_SIZE;

	if(!(ret = malloc(size)))
		return -1;

	memset(ret, 0, size);

	mpz_inits(m, c, NULL);

	while(left > 0) {
		int from = in_len - left;
		int to = (i + 1) * LCP_BLOCK_SIZE;
		char sz = (char)(left > LCP_BUF_SIZE) ? (LCP_BUF_SIZE) : (left);
		size_t enc_len = 0;	

		memset(block, 0, LCP_BLOCK_SIZE);
		block[0] = 0x01;
		block[1] = sz;
		memcpy(block + 2, in + from, sz);

		mpz_import(m, LCP_BLOCK_SIZE, 1, sizeof(block[0]),
				0, 0, block);

		mpz_powm(c, m, pub.e, pub.n);

		memset(block, 0, LCP_BLOCK_SIZE);

		mpz_export(block, &enc_len, 1, sizeof(char), 0, 0, c);

		memcpy(ret + to - enc_len, block, enc_len);

		left -= sz;
		i++;
	}

	*out = ret;
	*out_len = size;
	mpz_clears(m, c, NULL);
	return 0;
} 


LCP_API int lcp_decrypt(char **out, int *out_len, char *in, int in_len, 
		struct lcp_pvt_key pvt)
{
	int i;
	int num = in_len / LCP_BLOCK_SIZE;
	int msg_idx = 0;
	char block[LCP_BLOCK_SIZE];
	int size = num * LCP_BUF_SIZE;
	char *ret;
	int ret_len = 0;

	mpz_t m;
	mpz_t c;

	if(!(ret = malloc(size)))
		return -1;

	memset(ret, 0, size);

	mpz_inits(m, c, NULL);

	for(i = 0; i < num; i++) {
		mpz_import(c, LCP_BLOCK_SIZE, 1, sizeof(char), 0, 0, 
				in + (i * LCP_BLOCK_SIZE));

		mpz_powm(m, c, pvt.d, pvt.n);

		mpz_export(block, NULL, 1, sizeof(char), 0, 0, m);

		ret_len += block[1];
		memcpy(ret + (i * LCP_BUF_SIZE), block + 2, LCP_BUF_SIZE);
	}

	*out = ret;
	*out_len = ret_len;
	mpz_clears(m, c, NULL);
	return msg_idx;
}
