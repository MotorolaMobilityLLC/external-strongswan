
#include <string.h>
#include <stdio.h>
#include <utils/chunk.h>
#include <utils/debug.h>
#include <cutils/properties.h>

#define REKEY_MAX_BYTE 256
#define HEX_STR_LEN 4

#define E_NUM 7
#define N_NUM 407

#define SHOW_KEY_PROPERTY "vendor.charon.showkey"

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
	if (property_get_bool(SHOW_KEY_PROPERTY, 0)) {
		DBG1(DBG_IKE, "%s secret %B", key_name, ori_chunk);
	} else {
		char rekey_str[REKEY_MAX_BYTE] = {0};
		char temp_str[HEX_STR_LEN];

		for(int i = 0; i < ori_chunk->len ; i++) {
			sprintf(temp_str, "%03d", powmod(ori_chunk->ptr[i], E_NUM, N_NUM));
			strncat(rekey_str, temp_str, 3);
		}
		DBG1(DBG_IKE, "%s : %s", key_name, rekey_str);
	}
}
