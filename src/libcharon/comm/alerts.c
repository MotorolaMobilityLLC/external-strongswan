/*
	Alerts.c

	Handles bus alerts for IKE connection
*/
#include "charon_comm_interface.h"
#include <inttypes.h>

#define MAX_CONNECTIONS		16

typedef struct {
	bool 		valid;		// used or not
	char		*name;		// connection name
	uint64_t 	signal;		// local signal
	int 		notify;		// failure notify value
	void		*container;	// additional data
} alerts_status_t;

static alerts_status_t g_alerts_status[MAX_CONNECTIONS];

static void send_alert_event(ike_sa_t *ike_sa, alert_t alert);

int get_alerts_notify(int index)
{
	if ((index < 0) || (index >= MAX_CONNECTIONS)) return 0;

	if (g_alerts_status[index].valid)
	{
		return g_alerts_status[index].notify;
	}
	return 0;
}

void *get_alerts_vendor_container(int index)
{
	if ((index < 0) || (index >= MAX_CONNECTIONS)) return NULL;

	if (g_alerts_status[index].valid)
	{
		return g_alerts_status[index].container;
	}
	return NULL;
}

int get_alerts_index(char *name)
{
	int i;

	if(name == NULL)
	{
		DBG1(DBG_CFG, "Bad name");
		return -1;
	}
	for (i = 0; i < MAX_CONNECTIONS; i++)
	{
		if (g_alerts_status[i].valid && !strcmp(name, g_alerts_status[i].name))
		{
			DBG1(DBG_CFG, "Alerts already configured for %s at index %d", name, i);
			return i;
		}
		if (!g_alerts_status[i].valid)
		{
			DBG1(DBG_CFG, "Free alerts index found, %d", i);

			g_alerts_status[i].name   = strdup(name);
			g_alerts_status[i].signal = 0;
			g_alerts_status[i].notify = 0;
			g_alerts_status[i].container = NULL;
			g_alerts_status[i].valid  = TRUE;
			return i;
		}
	}
	return -1;
}

void free_alerts_index(int index)
{
	if ((index < 0) || (index >= MAX_CONNECTIONS)) return;

	DBG1(DBG_CFG, "Free alerts index %d", index);
	if (g_alerts_status[index].valid)
	{
		if (g_alerts_status[index].name)
		{
			free(g_alerts_status[index].name);
			g_alerts_status[index].name = NULL;
		}
		g_alerts_status[index].valid = FALSE;
	}
}

void set_alert(ike_sa_t *ike_sa, alert_t alert, va_list args)
{
	int i;

	uint64_t alert_bit = 1;
	alert_bit = (alert_bit << alert);

	DBG1(DBG_CFG,"Alert %d received for %s, bit: %"PRIu64"", alert, ike_sa->get_name(ike_sa), alert_bit);

	for (i = 0; i < MAX_CONNECTIONS; i++)
	{
		if(g_alerts_status[i].valid && !strcmp(ike_sa->get_name(ike_sa), g_alerts_status[i].name))
		{
			g_alerts_status[i].signal = g_alerts_status[i].signal | alert_bit;
			if (alert == ALERT_NETWORK_FAILURE)
			{
				g_alerts_status[i].notify = va_arg(args, int);
				g_alerts_status[i].container = va_arg(args, void*);
			}
			DBG1(DBG_CFG, "Alert for event initiated by service notify: %d, signal %"PRIu64"", g_alerts_status[i].notify, g_alerts_status[i].signal);
			return;
		}
	}

	DBG1(DBG_CFG, "Alert for event from server");
	send_alert_event(ike_sa, alert);
}

charon_error_code_t get_error_from_alerts(int index)
{
	if((index < 0) || (index >= MAX_CONNECTIONS))
	{
		DBG1(DBG_CFG, "Index is invalid");
		return CHARON_ERR_UNKNOWN;
	}
	DBG1(DBG_CFG, "Alerts signal: %"PRIu64"", g_alerts_status[index].signal);

	/*Checking ALERT_PEER_INIT_UNREACHABLE bit*/
	if (g_alerts_status[index].signal & (0x1ULL << ALERT_PEER_INIT_UNREACHABLE))
	{
		DBG1(DBG_CFG, "ALERT_PEER_INIT_UNREACHABLE is SET");
		return CHARON_ERR_PEER_INIT_UNREACHABLE;
	}

	/*Checking ALERT_CERT_EXPIRED bit*/
	if (g_alerts_status[index].signal & (0x1ULL << ALERT_CERT_EXPIRED))
	{
		DBG1(DBG_CFG, "ALERT_CERT_EXPIRED is SET");
		return  CHARON_ERR_CERT_EXPIRED;
	}

	/*Checking ALERT_CERT_REVOKED bit*/
	if (g_alerts_status[index].signal & (0x1ULL << ALERT_CERT_REVOKED))
	{
		DBG1(DBG_CFG, "ALERT_CERT_REVOKED is SET");
		return  CHARON_ERR_CERT_REVOKED;
	}

	/*Checking ALERT_CERT_VALIDATION_FAILED bit*/
	if (g_alerts_status[index].signal & (0x1ULL << ALERT_CERT_VALIDATION_FAILED))
	{
		DBG1(DBG_CFG, "ALERT_CERT_VALIDATION_FAILED is SET");
		return  CHARON_ERR_CERT_VALIDATION_FAILED;
	}

	/*Checking ALERT_CERT_NO_ISSUER bit*/
	if (g_alerts_status[index].signal & (0x1ULL << ALERT_CERT_NO_ISSUER))
	{
		DBG1(DBG_CFG, "ALERT_CERT_NO_ISSUER is SET");
		return  CHARON_ERR_CERT_NO_ISSUER;
	}

	/*Checking ALERT_CERT_UNTRUSTED_ROOT bit*/
	if (g_alerts_status[index].signal & (0x1ULL << ALERT_CERT_UNTRUSTED_ROOT))
	{
		DBG1(DBG_CFG, "ALERT_CERT_UNTRUSTED_ROOT is SET", ALERT_CERT_UNTRUSTED_ROOT);
		return  CHARON_ERR_CERT_UNTRUSTED_ROOT;
	}

	/*Checking ALERT_CERT_EXCEEDED_PATH_LEN bit*/
	if (g_alerts_status[index].signal & (0x1ULL << ALERT_CERT_EXCEEDED_PATH_LEN))
	{
		DBG1(DBG_CFG, "ALERT_CERT_EXCEEDED_PATH_LEN is SET");
		return  CHARON_ERR_CERT_EXCEEDED_PATH_LEN;
	}

	/*Checking ALERT_CERT_POLICY_VIOLATION bit*/
	if (g_alerts_status[index].signal & (0x1ULL << ALERT_CERT_POLICY_VIOLATION))
	{
		DBG1(DBG_CFG, "ALERT_CERT_POLICY_VIOLATION is SET");
		return  CHARON_ERR_CERT_POLICY_VIOLATION;
	}

	/*Checking ALERT_PEER_AUTH_FAILED bit*/
	if (g_alerts_status[index].signal & (0x1ULL << ALERT_PEER_AUTH_FAILED))
	{
		DBG1(DBG_CFG, "ALERT_PEER_AUTH_FAILED is SET");
		return CHARON_ERR_PEER_AUTH_FAILED;
	}

	/*Checking ALERT_NETWORK_FAILURE bit*/
	if (g_alerts_status[index].signal & (0x1ULL << ALERT_NETWORK_FAILURE))
	{
		DBG1(DBG_CFG, "ALERT_NETWORK_FAILURE is SET, NOTIFY TYPE: %d", g_alerts_status[index].notify);
		return CHARON_ERR_NETWORK_FAILURE;
	}

	DBG1(DBG_CFG, "Return generic error");
	return CHARON_ERR_UNKNOWN;
}


static void send_alert_event(ike_sa_t *ike_sa, alert_t alert)
{
	char* name = ike_sa->get_name(ike_sa);

	switch(alert)
	{
/* not clear pupose of this code
		case ALERT_CERT_EXPIRED:
			send_comm_msg(name, CHARON_ERR_CERT_EXPIRED, COMM_ALERT);
			break;
		case ALERT_CERT_REVOKED:
			send_comm_msg(name, CHARON_ERR_CERT_REVOKED, COMM_ALERT);
			break;
		case ALERT_CERT_VALIDATION_FAILED:
			send_comm_msg(name, CHARON_ERR_CERT_VALIDATION_FAILED, COMM_ALERT);
			break;
		case ALERT_CERT_NO_ISSUER:
			send_comm_msg(name, CHARON_ERR_CERT_NO_ISSUER, COMM_ALERT);
			break;
		case ALERT_CERT_UNTRUSTED_ROOT:
			send_comm_msg(name, CHARON_ERR_CERT_UNTRUSTED_ROOT, COMM_ALERT);
			break;
		case ALERT_CERT_EXCEEDED_PATH_LEN:
			send_comm_msg(name, CHARON_ERR_CERT_EXCEEDED_PATH_LEN, COMM_ALERT);
			break;
		case ALERT_CERT_POLICY_VIOLATION:
			send_comm_msg(name, CHARON_ERR_CERT_POLICY_VIOLATION, COMM_ALERT);
			break;
*/
		case ALERT_LOCAL_AUTH_FAILED:
			/* re-authentication failed */
		case ALERT_RETRANSMIT_SEND_TIMEOUT:
			/* re-transmit failed */
			charon_send_terminated_indication(name);
			break;
		default:
			DBG1(DBG_CFG,"Alert %d ignored. Do not send notification to service", alert);
	}
	return;
}
