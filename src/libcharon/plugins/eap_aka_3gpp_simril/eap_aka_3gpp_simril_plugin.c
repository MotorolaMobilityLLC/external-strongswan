/*
 * Copyright (C) 2014 Dragos Vingarzan
 * Core Network Dynamics / OpenEPC
 * dragos -at- corenetdynamics dot com
 *
 * Soft-AKA implementation for the 3GPP flavor of AKA - Rijndael/Milenage used
 * instead of SHA-1.
 *
 * This module is based on eap_aka_3gpp2 skeleton by
 * Copyright (C) 2008-2009 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#include "eap_aka_3gpp_simril_plugin.h"
#include "eap_aka_3gpp_simril_card.h"

#include <daemon.h>

typedef struct private_eap_aka_3gpp_simril_t private_eap_aka_3gpp_simril_t;

/**
 * Private data of an eap_aka_3gpp_simril_t object.
 */
struct private_eap_aka_3gpp_simril_t {

	/**
	 * Public eap_aka_3gpp_simril_plugin_t interface.
	 */
	eap_aka_3gpp_simril_plugin_t public;

	/**
	 * SIM card
	 */
	eap_aka_3gpp_simril_card_t *card;
};

METHOD(plugin_t, get_name, char*,
	private_eap_aka_3gpp_simril_t *this)
{
	return "eap-aka-3gpp-simril";
}

/**
 * Try to instanciate 3gpp functions and card/provider backends
 */
static bool register_functions(private_eap_aka_3gpp_simril_t *this,
							   plugin_feature_t *feature, bool reg, void *data)
{
	if (reg)
	{
		this->card = eap_aka_3gpp_simril_card_create();
		if (!this->card)
		{
			return FALSE;
		}
		return TRUE;
	}
	this->card->destroy(this->card);
	this->card = NULL;
	return TRUE;
}

/**
 * Callback providing our card to register
 */
static simaka_card_t* get_card(private_eap_aka_3gpp_simril_t *this)
{
	return &this->card->card;
}


METHOD(plugin_t, get_features, int,
	private_eap_aka_3gpp_simril_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((void*)register_functions, NULL),
			PLUGIN_PROVIDE(CUSTOM, "eap-aka-3gpp-simril-functions"),
				PLUGIN_DEPENDS(PRF, PRF_KEYED_SHA1),
		PLUGIN_CALLBACK(simaka_manager_register, get_card),
			PLUGIN_PROVIDE(CUSTOM, "aka-card"),
				PLUGIN_DEPENDS(CUSTOM, "aka-manager"),
				PLUGIN_DEPENDS(CUSTOM, "eap-aka-3gpp-simril-functions"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_eap_aka_3gpp_simril_t *this)
{
	free(this);
}

/**
 * See header
 */
plugin_t *eap_aka_3gpp_simril_plugin_create()
{
	private_eap_aka_3gpp_simril_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}

