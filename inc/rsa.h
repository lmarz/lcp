#ifndef _LCP_RSA_H
#define _LCP_RSA_H

#include <gmp.h>

#include "define.h"

#define LCP_MODULUS_SIZE     1024
#define LCP_BLOCK_SIZE       (LCP_MODULUS_SIZE/8)
#define LCP_BUF_SIZE         (LCP_BLOCK_SIZE-2)
#define LCP_BUFFER_SIZE      ((LCP_MODULUS_SIZE/8)/2)


struct lcp_pvt_key {
	mpz_t n;
	mpz_t e;
	mpz_t d;
	mpz_t p;
	mpz_t q;
};

struct lcp_pub_key {
	mpz_t n;
	mpz_t e;
};


/*
 * Initialize a private key and setup the basic values.
 *
 * @pvt: Pointer to the private-key
 */
LCP_API void lcp_init_pvt(struct lcp_pvt_key *pvt);


/*
 * Initialize the public key and setup the basic values.
 *
 * @pub: Pointer to the public-key
 */
LCP_API void lcp_init_pub(struct lcp_pub_key *pub);


/*
 * 
 */
LCP_API void lcp_clear_pvt(struct lcp_pvt_key *pvt);


/*
 * 
 */
LCP_API void lcp_clear_pub(struct lcp_pub_key *pub);


/*
 * Generate both the privat and public keys, which can then be used to encrypt
 * messages using RSA. The keys will be generated everytime this function is
 * called. So to get a new pair of keys, just call this function again. It is
 * technically not required to free the keys when exiting, but it still is the
 * prefered way. Note that the functions assumes that both keys have already
 * been initialized, by calling both lcp_init_pvt() and lcp_init_pub().
 *
 * @pvt: Pointer to a private-key-struct
 * @pub: Pointer to a public-key-struct
 */
LCP_API void lcp_gen_keys(struct lcp_pvt_key *pvt, struct lcp_pub_key *pub);


/*
 * Encrypt a message using the public key. The message will be split in
 * blocks of 126 bytes with additional 2 bytes at the beginning for
 * padding. The final size of a block is therefore 128 bytes. Even if
 * the message is smaller, the block will still be streched out. Note
 * that memory is allocated in this function to write the encrypted
 * message to. So after using the buffer, please free the buffer to 
 * prevent memory-leaks.
 *
 * @out: Pointer to allocate and write the output to
 * @out_len: Pointer to write the length of the buffer to
 * @in: Buffer containing the message to encrypt
 * @in_len: The length of the in-buffer
 * @pub: The public-key to encrypt with
 *
 * Returns: 0 on success or -1 if an error occurred
 */
LCP_API int lcp_encrypt(char **out, int *out_len, char *in, int in_len, 
		struct lcp_pub_key pub);


/*
 * Decrypt a message using the private key. Note that the function will output
 * a buffer containing blocks of 126 bytes each for every decrypted message
 * block. The memory for the buffer will be allocated in this function.
 * Therefore after using the buffer, please free the buffer to prevent
 * memory-leaks.
 *
 * @out: Pointer to allocate and write the output to
 * @out_len: Pointer to write the length of the buffer to
 * @in: Buffer containing the message to decrypt
 * @in_len: The length of the in-buffer
 * @pvt: The private-key to decrypt with
 *
 * Returns: 0 on success or -1 if an error occurred
 */
LCP_API int lcp_decrypt(char **out, int *out_len, char *in, int in_len, 
		struct lcp_pvt_key pvt);

#endif
