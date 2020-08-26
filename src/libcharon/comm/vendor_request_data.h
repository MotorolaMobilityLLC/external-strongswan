#ifndef VENDOR_REQUEST_DATA_H
#define VENDOR_REQUEST_DATA_H

#include <daemon.h>

typedef struct vendor_request_data_t vendor_request_data_t;

struct vendor_request_data_t {
	/* get configuration type */
	configuration_attribute_type_t (*get_attribute_type)(vendor_request_data_t *this);

	/* return vendor data */
	chunk_t (*get_data)(vendor_request_data_t *this);

	/* is it empty data */
	bool (*is_empty)(vendor_request_data_t *this);

	/* destroy */
	void (*destroy)(vendor_request_data_t *this);
};

vendor_request_data_t* build_vendor_request_data(char *buffer, int *offset);
vendor_request_data_t* build_dns_request_data(host_t* host);

#endif /* VENDOR_REQUEST_DATA_H */