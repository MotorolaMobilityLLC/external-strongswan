#ifndef VENDOR_REQUEST_LIST_H
#define VENDOR_REQUEST_LIST_H

#include <daemon.h>

typedef struct vendor_request_list_t vendor_request_list_t;

struct vendor_request_list_t {
	/* get next request value */
        int (*get_next)(vendor_request_list_t *this);

	/* reset to list start */
        void (*reset)(vendor_request_list_t *this);

	/* destroy */
	void (*destroy)(vendor_request_list_t *this);
};

vendor_request_list_t* build_vendor_request_list(char *buffer);

#endif /* VENDOR_REQUEST_LIST_H */