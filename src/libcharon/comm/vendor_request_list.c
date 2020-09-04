#include "vendor_request_list.h"

typedef struct private_vendor_request_list_t private_vendor_request_list_t;

/**
 * Private data
 */
struct private_vendor_request_list_t {
	/**
	 * Public interface
	 */
	vendor_request_list_t public;

	/** Size */
	int size;

	/** Index */
	int index;

	/** Values */
	unsigned int *values;
};

METHOD(vendor_request_list_t, get_next, int,
	private_vendor_request_list_t *this)
{
	if (this->size && (this->index < this->size))
	{
		return this->values[this->index++];
	}
	return 0;
}

METHOD(vendor_request_list_t, reset, void,
	private_vendor_request_list_t *this)
{
	this->index = 0;
}

METHOD(vendor_request_list_t, destroy, void,
	private_vendor_request_list_t *this)
{
	if (this->values)
	{
		free(this->values);
	}
	free(this);
}

vendor_request_list_t* build_vendor_request_list(char *buffer)
{
	private_vendor_request_list_t *this;

	INIT(this,
		.public = {
			.get_next = _get_next,
			.reset = _reset,
			.destroy = _destroy,
		},
		.size = 0,
		.index = 0,
		.values = NULL,
	);
	if (buffer != NULL)
	{
		typedef struct {
			unsigned int count;
			unsigned short values[0];
		} packed_ushort_list_t;

		packed_ushort_list_t *request = (packed_ushort_list_t*)buffer;
		if (request->count)
		{
			this->size = request->count;
			this->values = calloc(this->size, sizeof(unsigned int));
			for (int i = 0; i < this->size; i++)
			{
				this->values[i] = request->values[i] & 0xFFFF;
			}
		}
	}
	return &this->public;
}
