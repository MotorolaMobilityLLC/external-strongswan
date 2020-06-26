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

/**
 * @defgroup eap_aka_3gpp_simril_card eap_aka_3gpp_simril_card
 * @{ @ingroup eap_aka_3gpp
 */

#ifndef EAP_AKA_3GPP_CARD_H_
#define EAP_AKA_3GPP_CARD_H_

#include <simaka_card.h>

typedef struct eap_aka_3gpp_simril_card_t eap_aka_3gpp_simril_card_t;

/**
 * SIM card implementation using a set of AKA functions.
 */
struct eap_aka_3gpp_simril_card_t {

	/**
	 * Implements simaka_card_t interface
	 */
	simaka_card_t card;

	/**
	 * Destroy a eap_aka_3gpp_simril_card_t.
	 */
	void (*destroy)(eap_aka_3gpp_simril_card_t *this);
};

/**
 * Create a eap_aka_3gpp_simril_card instance.
 *
 * @param f		AKA functions
 */
eap_aka_3gpp_simril_card_t *eap_aka_3gpp_simril_card_create();

#endif /** EAP_AKA_3GPP_CARD_H_ @}*/
