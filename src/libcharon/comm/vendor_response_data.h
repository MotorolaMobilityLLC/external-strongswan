#ifndef VENDOR_RESPONSE_DATA_H
#define VENDOR_RESPONSE_DATA_H

#include <daemon.h>

typedef struct vendor_response_data_t vendor_response_data_t;

struct vendor_response_data_t {
	/* pack data to service */
	char* (*pack)(vendor_response_data_t *this, char *buffer);

	/* get full length */
        int (*get_length)(vendor_response_data_t *this);

	/* destroy */
	void (*destroy)(vendor_response_data_t *this);
};

vendor_response_data_t* build_vendor_response_data(int type, chunk_t data);
vendor_response_data_t* build_empty_response_data();

#endif /* VENDOR_RESPONSE_DATA_H */