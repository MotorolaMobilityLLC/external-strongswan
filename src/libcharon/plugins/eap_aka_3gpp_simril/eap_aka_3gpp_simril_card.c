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

#include "eap_aka_3gpp_simril_card.h"
#include "charon_comm_interface.h"

typedef struct private_eap_aka_3gpp_simril_card_t private_eap_aka_3gpp_simril_card_t;

/**
 * Private data of an eap_aka_3gpp_simril_card_t object.
 */
struct private_eap_aka_3gpp_simril_card_t {

	/**
	 * Public eap_aka_3gpp_simril_card_t interface.
	 */
	eap_aka_3gpp_simril_card_t public;
};

METHOD(simaka_card_t, get_quintuplet, status_t,
	private_eap_aka_3gpp_simril_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN],
	char ik[AKA_IK_LEN], char res[AKA_RES_MAX], int *res_len, char *sa_name)
{
	sim_auth_resp_code_t status = AUTH_FAILURE;
	int ret;


	DBG1(DBG_IKE, "3gpp_simril_card get_quintuplet for %s", sa_name);
	ret = charon_process_sim_auth(sa_name, rand, autn, ck, ik, res, res_len, &status);
    if (ret != SUCCESS)
	{
		DBG1(DBG_IKE, "3gpp_simril_card send_ril_sim_handler failed");
		return FAILED;
	}

	DBG1(DBG_IKE, "3gpp_simril_card response status = %d, %d length", status, *res_len);
	switch(status)
	{
		case AUTH_SUCCESS:
			return SUCCESS;
		case AUTH_SYNC_FAIL:
        		DBG1(DBG_IKE, "3gpp_simril_card get_quintuplet: sync failure, overwrite RAND");
			memset(rand, 0x00, AKA_RAND_LEN);
			memcpy(rand, res, AKA_RES_MAX);
			return INVALID_STATE;
		case AUTH_FAILURE:
		default:
        		DBG1(DBG_IKE,  "3gpp_simril_card get_quintuplet failed");
			return FAILED;
	}
}

METHOD(simaka_card_t, resync, bool,
	private_eap_aka_3gpp_simril_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN])
{
	DBG1(DBG_IKE, "3gpp_simril_card resync, use RAND %b", rand, AKA_RAND_LEN);
	memcpy(auts, rand, AKA_AUTS_LEN);
	return TRUE;
}

METHOD(eap_aka_3gpp_simril_card_t, destroy, void,
	private_eap_aka_3gpp_simril_card_t *this)
{
	free(this);
}

/**
 * See header
 */
eap_aka_3gpp_simril_card_t *eap_aka_3gpp_simril_card_create()
{
	private_eap_aka_3gpp_simril_card_t *this;

	INIT(this,
		.public = {
			.card = {
				.get_triplet = (void*)return_false,
#ifdef VOWIFI_CFG
				.get_quintuplet2 = _get_quintuplet,
#else
				.get_quintuplet = _get_quintuplet,
#endif
				.resync = _resync,
				.get_pseudonym = (void*)return_null,
				.set_pseudonym = (void*)nop,
				.get_reauth = (void*)return_null,
				.set_reauth = (void*)nop,
			},
			.destroy = _destroy,
		},
	);

	return &this->public;
}
