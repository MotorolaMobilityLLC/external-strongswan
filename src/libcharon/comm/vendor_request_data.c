#include "vendor_request_data.h"

typedef struct private_vendor_request_data_t private_vendor_request_data_t;

/**
 * Private data
 */
struct private_vendor_request_data_t {
	/**
	 * Public interface
	 */
	vendor_request_data_t public;

	/** Type */
	int type;

	/** Data */
	chunk_t data;
};

/**
 * Packed attribute structure from service
*/
typedef struct {
	unsigned short type;
	unsigned short length;
	char data[];
} packed_vendor_request_data_t;

METHOD(vendor_request_data_t, get_attribute_type, configuration_attribute_type_t,
	private_vendor_request_data_t *this)
{
	return this->type;
}

METHOD(vendor_request_data_t, get_notify_type, notify_type_t,
	private_vendor_request_data_t *this)
{
	return this->type;
}

METHOD(vendor_request_data_t, get_data, chunk_t,
	private_vendor_request_data_t *this)
{
	return this->data;
}

METHOD(vendor_request_data_t, is_empty, bool,
	private_vendor_request_data_t *this)
{
	return (this->type == 0);
}

METHOD(vendor_request_data_t, destroy, void,
	private_vendor_request_data_t *this)
{
	if (this->data.ptr)
	{
		chunk_free(&this->data);
	}
	free(this);
}

vendor_request_data_t* build_vendor_request_data(char *buffer, int *offset)
{
	private_vendor_request_data_t *this;

	INIT(this,
		.public = {
			.get_attribute_type = _get_attribute_type,
			.get_notify_type = _get_notify_type,
			.get_data = _get_data,
			.is_empty = _is_empty,
			.destroy = _destroy,
		},
		.data = chunk_empty,
	);

	packed_vendor_request_data_t *packed = (packed_vendor_request_data_t*)(buffer + *offset);
	this->type = packed->type;
	if (packed->length)
	{
		chunk_t chunk = chunk_create(packed->data, packed->length);
		this->data = chunk_clone(chunk);
	}
	*offset += (packed->length + sizeof(packed_vendor_request_data_t));

	return &this->public;
}

vendor_request_data_t* build_dns_request_data(host_t* host)
{
	private_vendor_request_data_t *this;

	INIT(this,
		.public = {
			.get_attribute_type = _get_attribute_type,
			.get_notify_type = _get_notify_type,
			.get_data = _get_data,
			.is_empty = _is_empty,
			.destroy = _destroy,
		},
		.data = chunk_empty,
	);
	switch (host->get_family(host))
	{
		case AF_INET:
			this->type = INTERNAL_IP4_DNS;
			break;
		case AF_INET6:
			this->type = INTERNAL_IP6_DNS;
			break;
	}
	if (!host->is_anyaddr(host))
	{
		chunk_t chunk = host->get_address(host);
		this->data = chunk_clone(chunk);
	}

	return &this->public;
}