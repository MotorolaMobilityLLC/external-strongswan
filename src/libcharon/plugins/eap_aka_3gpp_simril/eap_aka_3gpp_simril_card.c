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

	char* sa_name;
};

METHOD(simaka_card_t, get_quintuplet, status_t,
	private_eap_aka_3gpp_simril_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN],
	char ik[AKA_IK_LEN], char res[AKA_RES_MAX], int *res_len)
{
	sim_auth_resp_code_t status = AUTH_FAILURE;
	int ret;

	DBG1(DBG_IKE, "WRAPPER: received RAND %b", rand, AKA_RAND_LEN);
	DBG1(DBG_IKE, "WRAPPER: received AUTN %b", autn, AKA_AUTN_LEN);

	ret = charon_process_sim_auth(this->sa_name, rand, autn, ck, ik, res, res_len, &status);
	if (ret == SUCCESS)
	{
		DBG1(DBG_IKE, "[WRAPPER]: Response received from SIM: res_len: %d \n",*res_len);
		DBG1(DBG_IKE, "computed Status %d", status);
		DBG1(DBG_IKE, "computed RES %b", res, AKA_RES_MAX);
		DBG1(DBG_IKE, "computed CK %b", ck, AKA_CK_LEN);
		DBG1(DBG_IKE, "computed IK %b", ik, AKA_IK_LEN);
	}
	else
	{
		DBG1(DBG_IKE, "[WRAPPER]: send_ril_sim_handler() API returned failure\n");
		return FAILED;
	}

	/* Handling Respose Code Received from Sim Auth API */
	switch (status)
	{
		case AUTH_SUCCESS:
    	    		DBG1(DBG_IKE, "[WRAPPER] get_quintuplet: CK, IK and RES generated Successfully \n");
			return SUCCESS;
		case AUTH_FAILURE:
        		DBG1(DBG_IKE,  "[WRAPPER] get_quintuplet: Error occoured!! \n");
			return FAILED;
		case AUTH_SYNC_FAIL:
        		DBG1(DBG_IKE, "[wrapper] get_quintuplet: Synch Failure... Overwriting RAND value with RES value \n");
			memset(rand,0x00,AKA_RAND_LEN);
			memcpy(rand,res,AKA_RES_MAX);
			return INVALID_STATE;
		default:
        		DBG1(DBG_IKE,  "[WRAPPER] get_quintuplet: Default case. Returning failure. \n");
			return FAILED;
	}
}

METHOD(simaka_card_t, resync, bool,
	private_eap_aka_3gpp_simril_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN])
{
	DBG1(DBG_IKE, "[WRAPPER]: Generating AUTS Using RAND(indirect RES) value %b", rand, AKA_RAND_LEN);
	memcpy(auts,rand,AKA_AUTS_LEN);
	DBG1(DBG_IKE, "[WRAPPER]: Computed AUTS %b", auts, AKA_AUTS_LEN);
	return TRUE;
}

METHOD(eap_aka_3gpp_simril_card_t, destroy, void,
	private_eap_aka_3gpp_simril_card_t *this)
{
	free(this);
}

METHOD(simaka_card_t, set_sa_name, void,
	private_eap_aka_3gpp_simril_card_t *this, char *name)
{
	DBG1(DBG_IKE, "[WRAPPER]: Set SA name as %s", name);
	this->sa_name = name;
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
				.get_quintuplet = _get_quintuplet,
				.resync = _resync,
				.get_pseudonym = (void*)return_null,
				.set_pseudonym = (void*)nop,
				.get_reauth = (void*)return_null,
				.set_reauth = (void*)nop,
				.set_sa_name = _set_sa_name,
			},
			.destroy = _destroy,
		},
	);

	return &this->public;
}

