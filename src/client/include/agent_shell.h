#ifndef COMMON_H
#define COMMON_H
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "cJSON.h"
#include "agent_process.h"

typedef struct command_shell_s command_shell;
struct command_shell_s {
	thread_handle* output_thread;
	void* data;
	process_handle* proc;
};

// initialize the command shell object
uint32_t shell_new(char* shell_command, char* parent_program, void* context, command_shell* shell);

// run a command in the given shell command
bool shell_run(command_shell* shell, char* command);

// clean-up the shell object
bool shell_free(command_shell* shell);
#endif