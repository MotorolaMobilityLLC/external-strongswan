#ifndef __comm_msg_h
#define __comm_msg_h

#include <stdbool.h>

typedef enum {
	CHARON_ERR_SUCCESS,			/* Success */
    	CHARON_ERR_UNKNOWN,   			/* IPSec tunnel fail for any other reasons */
    	CHARON_ERR_PEER_INIT_UNREACHABLE,   	/* ALERT_PEER_INIT_UNREACHABLE */
    	CHARON_ERR_CERT_EXPIRED,    		/* ALERT_CERT_EXPIRED */
    	CHARON_ERR_CERT_REVOKED,    		/* ALERT_CERT_REVOKED */
    	CHARON_ERR_CERT_VALIDATION_FAILED,  	/* ALERT_CERT_VALIDATION_FAILED */
    	CHARON_ERR_CERT_NO_ISSUER,  		/* ALERT_CERT_NO_ISSUER */
    	CHARON_ERR_CERT_UNTRUSTED_ROOT, 	/* ALERT_CERT_UNTRUSTED_ROOT */
    	CHARON_ERR_CERT_EXCEEDED_PATH_LEN,  	/* ALERT_CERT_EXCEEDED_PATH_LEN*/
    	CHARON_ERR_CERT_POLICY_VIOLATION,   	/* ALERT_CERT_POLICY_VIOLATION */
    	CHARON_ERR_PEER_AUTH_FAILED, 		/* ALERT_PEER_AUTH_FAILED */
    	CHARON_ERR_NETWORK_FAILURE, 		/* NETWORK FAILURE NOTIFY */
} charon_error_code_t;

typedef enum {
        /* Response Code for initiate a connection */
        RES_INITIATE,

        /* Response Code for add a connection */
        RES_ADD_CONN,

        /* Response Code for delete a connection */
        RES_DEL_CONN,

        /* Response Code for terminate connection */
        RES_TERMINATE,

        /* Communication Code for connection terminated indication */
        IND_TERMINATED,

        /* Communication Code for EAP-AKA authentication */
        IND_SIM_AUTH,
	RES_SIM_AUTH,

    	/* ADD ROUTE */
    	RES_ADD_ROUTE,

    	/* DELETE ROUTE */
    	RES_DEL_ROUTE,

	/* set interface response */
	RES_SET_INTERFACE,
} charon_response_type_t;

#define AKA_RAND_LEN	16
#define AKA_AUTN_LEN	16
#define AKA_IK_LEN	16
#define AKA_CK_LEN	16
#define AKA_RES_LEN	16

typedef enum {
        /* All fields are successfully generated */
        AUTH_SUCCESS,

        /* None of the fields are correct */
        AUTH_FAILURE,

        /* Only res and res_len fields are valid i.e. sync failure. Call for resync*/
        AUTH_SYNC_FAIL,
} sim_auth_resp_code_t;

typedef struct
{
	unsigned short length;
	charon_response_type_t type;

	union {
		struct {
			char *name;
			charon_error_code_t status;
			int notify;
		} add_conn, del_conn, terminate;

		struct {
			char *name;
			charon_error_code_t status;
			int notify;
			char *device;
			char *address;
			char *attributes;
			char *notifies;
			int mtu;
		} initiate;

		struct {
			charon_error_code_t status;
		} add_route, del_route;

		struct {
			char *name;
		} ind_terminated;

		struct {
			char *name;
    			char rand[AKA_RAND_LEN];
			char autn[AKA_AUTN_LEN];
		} ind_sim_auth;

		struct {
			sim_auth_resp_code_t status;
    			char ck[AKA_CK_LEN];
			char ik[AKA_IK_LEN];
			int res_len;
			char res[AKA_RES_LEN];
		} res_sim_auth;
	};

	/* length of the string buffer */
	uint16_t buflen;
	/* string buffer */
	char buffer[];
} charon_response_t;

#endif
