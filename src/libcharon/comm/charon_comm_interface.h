#ifndef __comm_interface_h
#define __comm_interface_h

#include <daemon.h>
#include "comm_msg.h"
#include "stroke_msg.h"

#define CHARON_HANDLE IPSEC_PIDDIR "/charoncomm.ctl"

void charon_send_conn_response(charon_response_type_t type, stroke_msg_t *msg);
void charon_send_route_response(charon_response_type_t type, stroke_msg_t *msg);
void charon_send_terminate_response(charon_error_code_t error, stroke_msg_t *msg, int index);
void charon_send_initate_failure(stroke_msg_t *msg, int index);
void charon_send_initiate_success(stroke_msg_t *msg, int index);
void charon_send_terminated_indication(char* name);
status_t charon_process_sim_auth(char* name, char *rand, char *autn,
	char *ck, char *ik, char *res, int *res_len, sim_auth_resp_code_t *status);

#endif
