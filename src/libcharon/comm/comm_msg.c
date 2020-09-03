#include <stdint.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include "daemon.h"
#include "charon_comm_interface.h"
#include "comm_msg.h"
#include "alerts.h"
#include "stroke_msg.h"
#include "vendor_response_data.h"

static charon_response_t *create_response_msg(charon_response_type_t type)
{
	charon_response_t *msg;

	INIT(msg,
		.type = type,
		.length = offsetof(charon_response_t, buffer),
	);
	return msg;
}

#define push_string(msg, field, str) \
	push_string_impl(msg, offsetof(charon_response_t, field), str)

static void push_string_impl(charon_response_t **msg, size_t offset, char *string)
{
	size_t cur_len = (*msg)->length, str_len;

	if (!string)
	{
		return;
	}
	str_len = strlen(string) + 1;
	if (cur_len + str_len >= UINT16_MAX)
	{
		(*msg)->length = UINT16_MAX;
		return;
	}
	while (cur_len + str_len > sizeof(charon_response_t) + (*msg)->buflen)
	{
		*msg = realloc(*msg, sizeof(charon_response_t) + (*msg)->buflen +
					   STROKE_BUF_LEN_INC);
		(*msg)->buflen += STROKE_BUF_LEN_INC;
	}
	(*msg)->length += str_len;
	strcpy((char*)*msg + cur_len, string);
	*(char**)((char*)*msg + offset) = (char*)cur_len;
}

#define push_array(msg, field, data, length) \
	push_array_impl(msg, offsetof(charon_response_t, field), data, length)

static void push_array_impl(charon_response_t **msg, size_t offset, char *data, int length)
{
	size_t cur_len = (*msg)->length;

	if (!data || !length)
	{
		return;
	}
	if (cur_len + length >= UINT16_MAX)
	{
		(*msg)->length = UINT16_MAX;
		return;
	}
	while (cur_len + length > sizeof(charon_response_t) + (*msg)->buflen)
	{
		*msg = realloc(*msg, sizeof(charon_response_t) + (*msg)->buflen +
					   STROKE_BUF_LEN_INC);
		(*msg)->buflen += STROKE_BUF_LEN_INC;
	}
	(*msg)->length += length;
	memcpy((char*)*msg + cur_len, data, length);
	*(char**)((char*)*msg + offset) = (char*)cur_len;
}

/*
	ADD_CONN and DEL_CONN responses always successful
*/
void charon_send_conn_response(charon_response_type_t type, stroke_msg_t *msg)
{
	charon_response_t *res = create_response_msg(type);

	push_string(&res, add_conn.name, msg->add_conn.name);
	res->add_conn.status = CHARON_ERR_SUCCESS;
	res->add_conn.notify = 0;
	fwrite(res, 1, res->length, msg->out);
	free(res);
}

/*
	ADD_ROUTE and DEL_ROUTE responses always successful
*/
void charon_send_route_response(charon_response_type_t type, stroke_msg_t *msg)
{
	charon_response_t *res = create_response_msg(type);

	res->add_route.status = CHARON_ERR_SUCCESS;
	fwrite(res, 1, res->length, msg->out);
	free(res);
}

/*
	TERMINATE only
*/
void charon_send_terminate_response(charon_error_code_t error, stroke_msg_t *msg, int index)
{
	charon_response_t *res = create_response_msg(RES_TERMINATE);

	int notify = 0;
	if (error != CHARON_ERR_SUCCESS)
	{
		error = get_error_from_alerts(index);
		notify = get_alerts_notify(index);
	}
	free_alerts_index(index);

	push_string(&res, terminate.name, msg->terminate.name);
	res->terminate.status = error;
	res->terminate.notify = notify;
	fwrite(res, 1, res->length, msg->out);
	free(res);
}

/*
	INITIATE failure
*/
void charon_send_initate_failure(stroke_msg_t *msg, int index)
{
	charon_response_t *res = create_response_msg(RES_INITIATE);
	charon_error_code_t error = get_error_from_alerts(index);
	linked_list_t *list = NULL;
	int notify = 0;

	if (error == CHARON_ERR_NETWORK_FAILURE)
	{
		notify = get_alerts_notify(index);
		list = get_alerts_vendor_container(index);
	}
	free_alerts_index(index);

	push_string(&res, initiate.name, msg->initiate.name);
	res->initiate.status = error;
	res->initiate.notify = notify;

	if (list)
	{
		vendor_response_data_t *data;
		int length = 0;

		enumerator_t *enumerator = list->create_enumerator(list);
		while (enumerator->enumerate(enumerator, &data))
		{
			length += data->get_length(data);
		}
		enumerator->destroy(enumerator);
		if (length > 0)
		{
			char *mem = calloc(length + sizeof(int), 1);
			char *tmp = mem + sizeof(int);

			*((unsigned int*)mem) = length;

			while (list->remove_first(list, &data) == SUCCESS)
			{
				tmp = data->pack(data, tmp);
				data->destroy(data);
			}
			push_array(&res, initiate.notifies, mem, length + sizeof(int));
			free(mem);
		}
		list->destroy(list);
	}

	fwrite(res, 1, res->length, msg->out);
	free(res);
}

static char* get_notifies(ike_sa_t *ike_sa, int *total)
{
	linked_list_t *vendor_notifies = linked_list_create();
	int length = ike_sa->get_vendor_notifies(ike_sa, vendor_notifies);

	if (length)
	{
		vendor_response_data_t *notify;

		char *mem = calloc(length + sizeof(int), 1);
		char *tmp = mem + sizeof(int);

		*((unsigned int*)mem) = length;

		while (vendor_notifies->remove_first(vendor_notifies, &notify) == SUCCESS)
		{
			tmp = notify->pack(notify, tmp);
			notify->destroy(notify);
		}
		vendor_notifies->destroy(vendor_notifies);

		*total = length + sizeof(int);
		return mem;
	}
	vendor_notifies->destroy(vendor_notifies);
	return NULL;
}

static char* get_attributes(ike_sa_t *ike_sa, int *total)
{
	linked_list_t *vendor_attributes = linked_list_create();
	int length = ike_sa->get_configuration_attributes(ike_sa, vendor_attributes);

	if (length)
	{
		vendor_response_data_t *attr;

		char *mem = calloc(length + sizeof(int), 1);
		char *tmp = mem + sizeof(int);

		*((unsigned int*)mem) = length;

		while (vendor_attributes->remove_first(vendor_attributes, &attr) == SUCCESS)
		{
			tmp = attr->pack(attr, tmp);
			attr->destroy(attr);
		}
		vendor_attributes->destroy(vendor_attributes);

		*total = length + sizeof(int);
		return mem;
	}
	vendor_attributes->destroy(vendor_attributes);
	return NULL;
}

static char* get_addresses(ike_sa_t *ike_sa, int cnt)
{
	enumerator_t *enumerator;
	host_t* address;
	int pos = 0, len = INET6_ADDRSTRLEN * cnt + 1 + cnt;
	char* mem = calloc(len, 1);

	enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, TRUE);
	while (enumerator->enumerate(enumerator, &address))
	{
		chunk_t data = address->get_address(address);
		if (address->get_family(address) == AF_INET)
		{
			if ((len - pos) < INET_ADDRSTRLEN)
			{
				pos++;
              			break;
			}
			if (data.len > 0)
			{
				inet_ntop(AF_INET, data.ptr, mem + pos, (len - pos));
			}
		}
		else
		{
			if ((len - pos) < INET6_ADDRSTRLEN)
			{
				pos++;
				break;
			}
			if (data.len > 0)
       			{
				inet_ntop(AF_INET6, data.ptr, mem + pos, (len - pos));
			}
		}
		strcat(mem, ",");
		pos = strlen(mem);
	}
	enumerator->destroy(enumerator);

	if(pos == 0)
	{
		free(mem);
		return NULL;
	}
	else
	{
		mem[pos - 1] = 0;
	}
	return mem;
}

/*
	INITIATE success
*/
void charon_send_initiate_success(stroke_msg_t *msg, int index)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;

	charon_response_t *res = create_response_msg(RES_INITIATE);
	free_alerts_index(index);

	push_string(&res, initiate.name, msg->initiate.name);
	res->initiate.status = CHARON_ERR_SUCCESS;

	enumerator = charon->controller->create_ike_sa_enumerator(
						charon->controller, TRUE);
	while (enumerator->enumerate(enumerator, &ike_sa))
	{
		if (streq(msg->initiate.name, ike_sa->get_name(ike_sa)))
		{
			char *data = NULL;
			int length = 0;

			push_string(&res, initiate.device, ike_sa->get_tun_name(ike_sa));
			res->initiate.mtu = ike_sa->get_mtu(ike_sa);

			/* Addresses */
			data = get_addresses(ike_sa, 4);
			if (data)
			{
				push_string(&res, initiate.address, data);
				free(data);
			}

			/* attributes */
			data = get_attributes(ike_sa, &length);
			if (data)
			{
				push_array(&res, initiate.attributes, data, length);
				free(data);
			}

			/* notifies */
			data = get_notifies(ike_sa, &length);
			if (data)
			{
				push_array(&res, initiate.notifies, data, length);
				free(data);
			}

			/* end */
    			ike_sa->set_handover(ike_sa, 0);
    			DBG1(DBG_CFG,"Initiate completed, reset handover flag");
			break;
		}
	}
	enumerator->destroy(enumerator);

	fwrite(res, 1, res->length, msg->out);
	free(res);
}

// send message to service via client socket
static int send_message(void* msg, int length)
{
	struct sockaddr_un server;
	int addr_len;

	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG1(DBG_CFG, "Failed to create client socket, %s", strerror(errno));
		return sock;
	}

        memset(&server, 0, sizeof(server));

        /* ABSTRACT namespace is only possible for Java */
	server.sun_family  = AF_LOCAL;
        server.sun_path[0] = 0;
	memcpy(server.sun_path + 1, CHARON_HANDLE, strlen(CHARON_HANDLE));
	addr_len = strlen(CHARON_HANDLE) + offsetof(struct sockaddr_un, sun_path) + 1;
	if (connect(sock, (struct sockaddr*)&server, addr_len) < 0)
	{
		DBG1(DBG_CFG, "Failed to connect to server, %s", strerror(errno));
		close(sock);
		return (-1);
	}

	if (write(sock, msg, length) < 0)
	{
		DBG1(DBG_CFG, "Failed to send data to server, %s", strerror(errno));
		close(sock);
		return (-1);
	}
	return sock;
}

/*
	TERMINATED indication
*/
void charon_send_terminated_indication(char* name)
{
	charon_response_t *ind = create_response_msg(IND_TERMINATED);
	push_string(&ind, ind_terminated.name, name);

	int sock = send_message(ind, ind->length);
	if (sock > 0)
	{
		close(sock);
	}
	free(ind);
}

/*
	Process SIM authentication (request - response)
*/
status_t charon_process_sim_auth(char* name, char *rand, char *autn, char *ck, char *ik, char *res, int *res_len, sim_auth_resp_code_t *status)
{
	struct timeval timeout;
	fd_set readset;

	charon_response_t *ind = create_response_msg(IND_SIM_AUTH);

	push_string(&ind, ind_sim_auth.name, name);
	memcpy(ind->ind_sim_auth.rand, rand, AKA_RAND_LEN);
	memcpy(ind->ind_sim_auth.autn, autn, AKA_AUTN_LEN);

	int sock = send_message(ind, ind->length);
	free(ind);
	if (sock < 0)
	{
		return FAILED;
	}

	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	FD_ZERO(&readset);
	FD_SET(sock, &readset);

	int result = select(sock + 1, &readset, NULL, NULL, &timeout);
	if (FD_ISSET(sock, &readset))
	{
		charon_response_t resp;
		memset(&resp, 0, sizeof(resp));

		int read = recv(sock, &resp, sizeof(resp), 0);
		if (read > 0)
		{
			if (resp.type == RES_SIM_AUTH)
			{
				*status = resp.res_sim_auth.status;
				memcpy(ck, resp.res_sim_auth.ck, AKA_CK_LEN);
				memcpy(ik, resp.res_sim_auth.ik, AKA_IK_LEN);
				*res_len = resp.res_sim_auth.res_len;
				if (resp.res_sim_auth.res_len)
				{
					memcpy(res, resp.res_sim_auth.res, resp.res_sim_auth.res_len);
				}
				close(sock);
				return SUCCESS;
			}
			else
			{
				DBG1(DBG_CFG, "Unknown response type = %d", resp.type);
			}
		}
		else
		{
			if (read < 0)
			{
				DBG1(DBG_CFG, "Receive failed, %s", strerror(errno));
			}
			else
			{
				DBG1(DBG_CFG, "Connection aborted");
			}
		}
	}
       	else
	{
		if (result < 0)
		{
               		DBG1(DBG_CFG, "Select failed, %s", strerror(errno));
		}
       		else
		{
               		DBG1(DBG_CFG, "Authentication timeout");
		}
	}
	close(sock);
	return FAILED;
}
