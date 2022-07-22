#pragma once
#ifndef UTILITY_H
#define UTILITY_H
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "cJSON.h"
#include "agent_protocol.h"
#include "agent_commands.h"

#define MEM_ALLOC(T) calloc(T, sizeof(uint8_t))
#define OBJ_ALLOC(T) ((T*)calloc(1, sizeof(T)))
#define ZERO(T) (T*){0}
#define FREE(T)			\
	do {				\
		if (T) {		\
			free(T);	\
			T = 0;		\
		}				\
	} while(0)

bool hex_to_ascii(void const* buffer, size_t buffer_size, char* ascii_buffer, size_t ascii_buffer_size);
uint32_t custom_FNV1a32(size_t buffer_size, uint8_t* buffer);
void rc4(size_t buffer_size, uint8_t* buffer);
char* unicode_to_ascii(wchar_t* unicode_string);
char* normalize_text(uint8_t * buffer, uint32_t buffer_size);
uint32_t system_fingerprint(void);
bool gen_random_string(uint32_t seed, size_t buffer_size, char* buffer);
char* base64_encode(size_t buffer_size, uint8_t * buffer);
uint8_t* base64_decode(char* text, size_t * buffer_size);
void sleep_ms(uint32_t milliseconds);
char* rstrstr(char* __restrict s1, char* __restrict s2);
cJSON* convert_to_JSON(packet * pck);
int32_t get_OS_error();
char* get_OS_error_as_string();
void set_OS_error(uint32_t error_code);
char* serialize_command_result(command_result * cmd_result);
bool expand_environment_variables(char* orig_path, char* expanded_path, size_t expanded_path_size);
void program_run_info_free(program_run_info * info);
void process_intercepted_free(process_intercepted * proc);
bool verify_program_termination(process_intercepted * proc);
bool wait_for_process_termination(process_intercepted * proc);
#endif
