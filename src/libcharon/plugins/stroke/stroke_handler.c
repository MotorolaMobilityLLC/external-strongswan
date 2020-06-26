/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "stroke_handler.h"

#include <daemon.h>
#include <collections/linked_list.h>
#include <threading/rwlock.h>

typedef struct private_stroke_handler_t private_stroke_handler_t;

/**
 * Private data of an stroke_handler_t object.
 */
struct private_stroke_handler_t {

	/**
	 * Public stroke_handler_t interface.
	 */
	stroke_handler_t public;

	/**
	 * List of connection specific attributes, as attributes_t
	 */
	linked_list_t *attrs;

	/**
	 * rwlock to lock access to pools
	 */
	rwlock_t *lock;
};

/**
 * Attributes assigned to a connection
 */
typedef struct {
	/** name of the connection */
	char *name;
	/** list of DNS attributes, as host_t */
	linked_list_t *dns;
#ifdef VOWIFI_CFG
	/** list of P-CSCF attributes, as host_t */
	linked_list_t *pcscf;
	/** list of IMEI attributes */
	linked_list_t *imei;
#endif
} attributes_t;

#ifdef VOWIFI_CFG
#define IMEI_MAX 	33
typedef struct {
	/* Device IMEI number*/
	char imei[IMEI_MAX];
} imei_t;
#endif

/**
 * Destroy an attributes_t entry
 */
static void attributes_destroy(attributes_t *this)
{
	this->dns->destroy_offset(this->dns, offsetof(host_t, destroy));
	free(this->name);
	free(this);
}

CALLBACK(attr_filter, bool,
	void *lock, enumerator_t *orig, va_list args)
{
	configuration_attribute_type_t *type;
	chunk_t *data;
	host_t *host;

	VA_ARGS_VGET(args, type, data);

	while (orig->enumerate(orig, &host))
	{
		switch (host->get_family(host))
		{
			case AF_INET:
				*type = INTERNAL_IP4_DNS;
				break;
			case AF_INET6:
				*type = INTERNAL_IP6_DNS;
				break;
			default:
				continue;
		}
		if (host->is_anyaddr(host))
		{
			*data = chunk_empty;
		}
		else
		{
			*data = host->get_address(host);
		}
		return TRUE;
	}
	return FALSE;
}

#ifdef VOWIFI_CFG
/**
 * Filter function to convert host to PCSCF configuration attributes
 */
CALLBACK(attr_pcscf_filter, bool,
	ike_sa_t *ike_sa, enumerator_t *orig, va_list args)
{
	configuration_attribute_type_t *type;
	chunk_t *data;
	host_t *host;

	VA_ARGS_VGET(args, type, data);

	while (orig->enumerate(orig, &host))
	{
		switch (host->get_family(host))
		{
			case AF_INET:
			switch (ike_sa->get_operator(ike_sa)) {
				case OPERATOR_TYPE_DEFAULT:
					*type = P_CSCF_IP4_ADDRESS;
					break;
				case OPERATOR_TYPE_TMO_ATT:
					*type = P_CSCF_IP4_ADDRESS_OPR_TYPE_1;
					break;
				case OPERATOR_TYPE_VZW:
					*type = P_CSCF_IP4_ADDRESS_OPR_TYPE_2;
					break;
				default:
					*type = P_CSCF_IP4_ADDRESS;
			}
			break;
			case AF_INET6:
			switch (ike_sa->get_operator(ike_sa)) {
				case OPERATOR_TYPE_DEFAULT:
					*type = P_CSCF_IP6_ADDRESS;
					break;
				case OPERATOR_TYPE_TMO_ATT:
					*type = P_CSCF_IP6_ADDRESS_OPR_TYPE_1;
					break;
				case OPERATOR_TYPE_VZW:
					*type = P_CSCF_IP6_ADDRESS_OPR_TYPE_2;
					break;
				default:
					*type = P_CSCF_IP6_ADDRESS;
			}
			break;
			default:
				continue;
		}
		if (host->is_anyaddr(host))
		{
			*data = chunk_empty;
		}
		else
		{
			*data = host->get_address(host);
		}
		return TRUE;
	}
	return FALSE;
}
/**
 * Filter function to convert host to PCSCF configuration attributes
 */
CALLBACK(attr_imei_filter, bool,
			void *lock, enumerator_t *orig, va_list args)
{
	configuration_attribute_type_t *type;
	chunk_t *data;
	imei_t *device_imei;

	VA_ARGS_VGET(args, type, data);

	while (orig->enumerate(orig, &device_imei))
	{
	    *type = DEVICE_IMEI;
	    *data = chunk_create(device_imei->imei, strlen(device_imei->imei));
		return TRUE;
	}
	return FALSE;
}
#endif

#ifdef VOWIFI_CFG
METHOD(attribute_handler_t, create_attribute_enumerator, enumerator_t*,
	private_stroke_handler_t *this, ike_sa_t *ike_sa,
	linked_list_t *vips, int attr_type)
#else
METHOD(attribute_handler_t, create_attribute_enumerator, enumerator_t*,
	private_stroke_handler_t *this, ike_sa_t *ike_sa,
	linked_list_t *vips)
#endif
{
	peer_cfg_t *peer_cfg;
	enumerator_t *enumerator;
	attributes_t *attr;

	ike_sa = charon->bus->get_sa(charon->bus);
	if (ike_sa)
	{
		peer_cfg = ike_sa->get_peer_cfg(ike_sa);
		this->lock->read_lock(this->lock);
		enumerator = this->attrs->create_enumerator(this->attrs);
		while (enumerator->enumerate(enumerator, &attr))
		{
			if (streq(attr->name, peer_cfg->get_name(peer_cfg)))
			{
				enumerator->destroy(enumerator);
#ifdef VOWIFI_CFG
				if (attr_type == 0)
				{
#endif
				return enumerator_create_filter(
									attr->dns->create_enumerator(attr->dns),
									attr_filter, this->lock,
									(void*)this->lock->unlock);
#ifdef VOWIFI_CFG
				}
				else if(attr_type == 1)
				{
					this->lock->unlock(this->lock);
					return enumerator_create_filter(
							attr->pcscf->create_enumerator(attr->pcscf),
							attr_pcscf_filter, ike_sa, NULL);
				}
				else if(attr_type == 2)
				{
					return enumerator_create_filter(
							attr->imei->create_enumerator(attr->imei),
							attr_imei_filter, this->lock,
							(void*)this->lock->unlock);
				}
#endif
			}
		}
		enumerator->destroy(enumerator);
		this->lock->unlock(this->lock);
	}
	return enumerator_create_empty();
}

METHOD(stroke_handler_t, add_attributes, void,
	private_stroke_handler_t *this, stroke_msg_t *msg)
{
#ifdef VOWIFI_CFG
	attributes_t *attr = NULL;
#endif
	if (msg->add_conn.me.dns)
	{
		enumerator_t *enumerator;
#ifndef VOWIFI_CFG
		attributes_t *attr = NULL;
#endif
		host_t *host;
		char *token;

		enumerator = enumerator_create_token(msg->add_conn.me.dns, ",", " ");
		while (enumerator->enumerate(enumerator, &token))
		{
			if (streq(token, "%config") || streq(token, "%config4"))
			{
				host = host_create_any(AF_INET);
			}
			else if (streq(token, "%config6"))
			{
				host = host_create_any(AF_INET6);
			}
			else
			{
				host = host_create_from_string(token, 0);
			}
			if (host)
			{
				if (!attr)
				{
					INIT(attr,
						.name = strdup(msg->add_conn.name),
						.dns = linked_list_create(),
#ifdef VOWIFI_CFG
						.pcscf = linked_list_create(),
						.imei = linked_list_create(),
#endif
					);
				}
				attr->dns->insert_last(attr->dns, host);
			}
			else
			{
				DBG1(DBG_CFG, "ignoring invalid DNS address '%s'", token);
			}
		}
		enumerator->destroy(enumerator);
#ifndef VOWIFI_CFG
		if (attr)
		{
			this->lock->write_lock(this->lock);
			this->attrs->insert_last(this->attrs, attr);
			this->lock->unlock(this->lock);
		}
#endif
	}
#ifdef VOWIFI_CFG
	if (msg->add_conn.pcscf)
	{
		enumerator_t *enumerator;
		host_t *host;
		char *token;

		enumerator = enumerator_create_token(msg->add_conn.pcscf, ",", " ");
		while (enumerator->enumerate(enumerator, &token))
		{
			if (streq(token, "%config") || streq(token, "%config4"))
			{
				host = host_create_any(AF_INET);
			}
			else if (streq(token, "%config6"))
			{
				host = host_create_any(AF_INET6);
			}
			else
			{
				host = host_create_from_string(token, 0);
			}
			if (host)
			{
				if (!attr)
				{
					INIT(attr,
						.name = strdup(msg->add_conn.name),
						.dns = linked_list_create(),
						.pcscf = linked_list_create(),
						.imei = linked_list_create(),
					);
				}
				attr->pcscf->insert_last(attr->pcscf, host);
			}
			else
			{
				DBG1(DBG_CFG, "ignoring invalid PCSCF address '%s'", token);
			}
		}
		enumerator->destroy(enumerator);
	}

	if (msg->add_conn.imei)
	{
		imei_t *device_imei;
		INIT(device_imei);
		if (device_imei)
		{
			strncpy(device_imei->imei, msg->add_conn.imei, IMEI_MAX - 1);
			DBG1(DBG_CFG, " Adding IMEI: '%s'", device_imei->imei);
			if (!attr)
			{
				INIT(attr,
					.name = strdup(msg->add_conn.name),
					.dns = linked_list_create(),
					.pcscf = linked_list_create(),
					.imei = linked_list_create(),
				);
			}
			attr->imei->insert_last(attr->imei, device_imei);
		}
		else
		{
			DBG1(DBG_CFG, "Failed to add attribute IMEI: '%s'", msg->add_conn.imei);
		}
	}
	if (attr)
	{
		this->lock->write_lock(this->lock);
		this->attrs->insert_last(this->attrs, attr);
		this->lock->unlock(this->lock);
	}
#endif
}

METHOD(stroke_handler_t, del_attributes, void,
	private_stroke_handler_t *this, stroke_msg_t *msg)
{
	enumerator_t *enumerator;
	attributes_t *attr;

	this->lock->write_lock(this->lock);
	enumerator = this->attrs->create_enumerator(this->attrs);
	while (enumerator->enumerate(enumerator, &attr))
	{
		if (streq(msg->del_conn.name, attr->name))
		{
			this->attrs->remove_at(this->attrs, enumerator);
			attributes_destroy(attr);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

METHOD(stroke_handler_t, destroy, void,
	private_stroke_handler_t *this)
{
	this->lock->destroy(this->lock);
	this->attrs->destroy_function(this->attrs, (void*)attributes_destroy);
	free(this);
}

/**
 * See header
 */
stroke_handler_t *stroke_handler_create()
{
	private_stroke_handler_t *this;

	INIT(this,
		.public = {
			.handler = {
				.handle = (void*)return_false,
				.release = (void*)return_false,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.add_attributes = _add_attributes,
			.del_attributes = _del_attributes,
			.destroy = _destroy,
		},
		.attrs = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
