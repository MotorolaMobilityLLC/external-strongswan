#include "vendor_response_data.h"

typedef struct private_vendor_response_data_t private_vendor_response_data_t;

/**
 * Private data
 */
struct private_vendor_response_data_t {
	/**
	 * Public interface
	 */
	vendor_response_data_t public;

	/** Type */
	int type;

	/** Data */
	chunk_t data;
};

/**
 * Packed attribute structure to service
*/
typedef struct {
	unsigned short type;
	unsigned short length;
	char data[];
} packed_vendor_response_data_t;

METHOD(vendor_response_data_t, get_length, int,
	private_vendor_response_data_t *this)
{
	return (sizeof(packed_vendor_response_data_t) + this->data.len);
}

METHOD(vendor_response_data_t, pack, char*,
	private_vendor_response_data_t *this, char *buffer)
{
	packed_vendor_response_data_t* packed = (packed_vendor_response_data_t*)buffer;
	packed->type = this->type;
	packed->length = this->data.len;
	if (packed->length)
	{
		memcpy(packed->data, this->data.ptr, packed->length);
	}
	return (buffer + get_length(this));
}

METHOD(vendor_response_data_t, destroy, void,
	private_vendor_response_data_t *this)
{
	free(this);
}

vendor_response_data_t* build_vendor_response_data(int type, chunk_t data)
{
	private_vendor_response_data_t *this;

	INIT(this,
		.public = {
			.pack = _pack,
			.get_length = _get_length,
			.destroy = _destroy,
		},
		.type = type,
		.data = data,
	);
	return &this->public;
}

vendor_response_data_t* build_empty_response_data()
{
	private_vendor_response_data_t *this;

	INIT(this,
		.public = {
			.pack = _pack,
			.get_length = _get_length,
			.destroy = _destroy,
		},
		.type = 0,
		.data = chunk_empty,
	);
	return &this->public;
}
