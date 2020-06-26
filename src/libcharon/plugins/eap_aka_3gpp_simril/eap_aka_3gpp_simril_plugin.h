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
 * @defgroup eap_aka_3gpp eap_aka_3gpp
 * @ingroup cplugins
 *
 * @defgroup eap_aka_3gpp_simril_plugin eap_aka_3gpp_simril_plugin
 * @{ @ingroup eap_aka_3gpp
 */

#ifndef EAP_AKA_3GPP_PLUGIN_H_
#define EAP_AKA_3GPP_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct eap_aka_3gpp_simril_plugin_t eap_aka_3gpp_simril_plugin_t;

/**
 * Plugin to provide a USIM card/provider using the 3GPP (TS 35.205->208)
 * standards.
 *
 * This plugin implements the standard of the 3GPP and not the one
 * of 3GGP2 ((S.S0055), completely in software.
 * The shared key used for authentication is from ipsec.secrets. The EAP
 * key should include in order: 16bytes for K, 16 bytes for OP and 6 bytes
 * for SQN. If too short, zero is filled to the right. The peers ID is
 * used to query it.
 * The AKA mechanism uses sequence numbers to detect replay attacks. The
 * peer stores the sequence number normally in a USIM and accepts
 * incremental sequence numbers (incremental for lifetime of the USIM). To
 * prevent a complex sequence number management, this implementation uses
 * a sequence number derived from time on the client, or from
 * configuration, yet that is a bit limited as write-back is not
 * implemented. It is initialized to the startup time of the daemon.
 * Default is to accept any SEQ numbers. This allows an attacker to do
 * replay attacks. But since you are using a Soft-AKA module and not a
 * hardware one (e.g. a future eap_usim_pcsc plugin, or eap_simaka_pcscc),
 * you are not very* safe anyway and this is provided more as a proof of
 * concept.
 *
 * The plugin also generates triplets, besides quintuplets. This is not
 * AKA per-se, but SIM authentication derived from USIM. Hence the
 * SRES/Kc are derived as for example to perform 2G authentication with a
 * newer and safer USIM for 3G/LTE.
 */
struct eap_aka_3gpp_simril_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** EAP_AKA_3GPP_PLUGIN_H_ @}*/
