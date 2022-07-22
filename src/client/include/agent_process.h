#pragma once
#ifndef PROCESS_H
#define PROCESS_H
#include <stdint.h>
#include <stdbool.h>
#include "agent_thread.h"
#include "agent_named_pipe.h"

typedef struct process_handle_s process_handle;
struct process_handle_s {
	uint32_t pid;
	uintptr_t handle;
	uintptr_t proc_stdin;
	uintptr_t proc_stdout;
};

uint32_t process_inject_shellcode(uint32_t pid, size_t buffer_size, uint8_t* buffer, thread_handle* thandle);

uint32_t process_run(char* program_name, char* arguments, char* parent_process, process_handle* phandle);

bool process_is_alive(process_handle* process);

bool process_is_alive_by_pid(uint32_t pid);

void process_free(process_handle* process, bool kill_process);

bool process_kill(uint32_t pid);

uint32_t get_pid(void);
#endif