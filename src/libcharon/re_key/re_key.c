
#include <string.h>
#include <stdio.h>
#include <utils/chunk.h>
#include <utils/debug.h>

#define REKEY_MAX_BYTE 256
#define HEX_STR_LEN 4

#define E_NUM 7
#define N_NUM 407

/**
 * Computes a^b mod c
 */
int powmod(long long a, long long b, int c) {
	int res = 1;
	while(b > 0) {
		if(b & 1) {
			res = (res * a) % c;
		}
		b = b >> 1;
		a = (a * a) % c;
	}
	return res;
}

/**
 * Print Encrypt original secret codes
 */
void rekey_secret_code(chunk_t *ori_chunk, char *key_name) {
	char rekey_str[REKEY_MAX_BYTE] = {0};
	char val[HEX_STR_LEN];

	for(int i = 0; i < ori_chunk->len ; i++) {
		sprintf(val,"%03d", powmod(ori_chunk->ptr[i], E_NUM, N_NUM) );
		strncat(rekey_str, val, 3);
	}

	DBG1(DBG_IKE, "%s : %s", key_name, rekey_str);
}