#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "agent_utility.h"
#include "mbedtls/base64.h"

char* base64_encode(size_t buffer_size, uint8_t* buffer) {
	size_t encoded_size = 0;
	char* encoded_data = ZERO(char);

	if (mbedtls_base64_encode(
		0,
		0,
		&encoded_size,
		buffer,
		buffer_size) != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) goto fail;

	encoded_data = MEM_ALLOC(encoded_size);
	if (!encoded_data) goto fail;

	if (mbedtls_base64_encode(
		(unsigned char*)encoded_data,
		encoded_size,
		&encoded_size,
		(unsigned char*)buffer,
		buffer_size
	)) goto fail;

	return encoded_data;
fail:
	FREE(encoded_data);
	return ZERO(char);
}

uint8_t* base64_decode(char* text, size_t* buffer_size) {
	size_t decoded_length = 0;	
	size_t text_lenght = strlen(text);
	uint8_t* buffer = ZERO(uint8_t);

	if (mbedtls_base64_decode(
		0,
		0,
		&decoded_length,
		(unsigned char*)text,
		text_lenght) != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) goto fail;

	buffer = MEM_ALLOC(decoded_length);
	if (!buffer) goto fail;

	if (mbedtls_base64_decode(
		(unsigned char*)buffer,
		decoded_length,
		&decoded_length,
		(unsigned char*)text,
		text_lenght
	)) goto fail;

	if (buffer_size) *buffer_size = decoded_length;
	return buffer;
fail:
	FREE(buffer);
	*buffer_size = 0;
	return 0;
}

bool hex_to_ascii(void const* buffer, size_t buffer_size, char* ascii_buffer, size_t ascii_buffer_size) {
	if (ascii_buffer_size < buffer_size * 2) goto fail;
	size_t j = 0;
	for (size_t i = 0; i < buffer_size; i++) {
		uint8_t h = (((uint8_t*)buffer)[i]) / 16;
		uint8_t l = (((uint8_t*)buffer)[i]) % 16;

		if (h < 10)
			ascii_buffer[j] = '0' + h;
		else
			ascii_buffer[j] = 'a' + h - 10;

		if (l < 10)
			ascii_buffer[j + 1] = '0' + l;
		else
			ascii_buffer[j + 1] = 'a' + l - 10;
		j += 2;

	}

	return true;
fail:
	return false;
}

uint32_t custom_FNV1a32(size_t buffer_size, uint8_t* buffer) {
	uint32_t fnvp = 0x01000193;
	uint32_t fnvob = 0x811c9dc5;
	uint32_t x = buffer_size & 0xff;
	uint32_t xorKey = x | x << 8 | x << 16 | x << 24;
	uint32_t h = fnvob;
	for (size_t i = 0; i < buffer_size; i++) {
		h ^= buffer[i];
		h *= fnvp;
	}
	return h ^ xorKey;
}

void rc4(size_t buffer_size, uint8_t* buffer) {
	uint8_t* payload = buffer + 32;
	
	uint8_t S[256] = { 0 };
	for (size_t i = 0; i < sizeof S; i++) {
		S[i] = i;
	}

	// KSA
	uint32_t j = 0;
	for (size_t i = 0; i < 256; i++) {
		j = (j + S[i] + buffer[i % 32]) % 256;
		uint8_t t = S[i];
		S[i] = S[j];
		S[j] = t;
	}

	// PRGA
	j = 0;
	for (size_t i = 0; i < buffer_size - 32; i++) {
		uint32_t im = (i + 1) % 256;
		j = (j + S[im]) % 256;
		uint8_t t = S[im];
		S[im] = S[j];
		S[j] = t;
		uint8_t k = S[(S[im] + S[j]) % 256];
		payload[i] ^= k;
	}
}

bool gen_random_string(uint32_t seed, size_t buffer_size, char* buffer) {
	srand(seed);
	for (uint32_t i = 0; i < buffer_size; i++) {
		uint32_t r = ((rand() ^ buffer_size) % 74) + 48;
		if ((r >= 58 && r < 65) || (r >= 91 && r < 97)) {
			i--;
			continue;
		}
		buffer[i] = (char)r;
	}
	return true;
}

char* rstrstr(char* __restrict s1, char* __restrict s2) {
	size_t  s1len = strlen(s1);
	size_t  s2len = strlen(s2);
	char* s;

	if (s2len > s1len)
		return ZERO(char);
	for (s = s1 + s1len - s2len; s >= s1; --s)
		if (strncmp(s, s2, s2len) == 0)
			return s;
	return ZERO(char);
}

cJSON* convert_to_JSON(packet* pck) {
	cJSON* result = ZERO(cJSON);
	char* tmp = MEM_ALLOC(pck->data_size + 1);
	if (!tmp) goto fail;
	memcpy(tmp, pck->data, pck->data_size);
	result = cJSON_Parse(tmp);
	FREE(tmp);

fail:
	return result;
}

char* get_OS_error_as_string() {
	int32_t error_code = get_OS_error();
	size_t size = snprintf(0, 0, "%d", error_code) + 1;
	char* error_str = MEM_ALLOC(size);
	sprintf(error_str, "%d", error_code);
	return error_str;
}

char* serialize_command_result(command_result* cmd_result) {
	cJSON* jpayload = ZERO(cJSON);
	char* payload = ZERO(char);

	// compose payload
	jpayload = cJSON_CreateObject();
	if (!jpayload) goto exit;

	// add data
	cJSON* jdata = cJSON_CreateString(cmd_result->data ? (char*)cmd_result->data : "");
	if (!jdata) goto exit;
	if (!cJSON_AddItemToObject(jpayload, "data", jdata)) goto exit;

	// add error result info
	cJSON* jerror = cJSON_CreateNumber(cmd_result->error_code);
	if (!jerror) goto exit;
	if (!cJSON_AddItemToObject(jpayload, "error", jerror)) goto exit;

	payload = cJSON_Print(jpayload);
	if (!payload) goto exit;

exit:
	if (jpayload) cJSON_Delete(jpayload);
	return payload;
}

void process_intercepted_free(process_intercepted* proc)
{
	event_free(proc->interceptor_event);
	proc->interceptor_event = ZERO(event_handle);

	pipe_free(proc->pipe);
	proc->pipe = ZERO(pipe_handle);

	process_free(proc->process, false);
	proc->process = ZERO(process_handle);

	FREE(proc);
}

void program_run_info_free(program_run_info* info) 
{
	message_packet_free(info->pck);
	info->pck = ZERO(packet);
	FREE(info);
}

bool verify_program_termination(process_intercepted* proc) {
	bool terminate = false;
	if (!process_is_alive_by_pid(proc->process_pid)) {
		// signal the event to terminate the interceptor remote thread (if defined)
		event_set(proc->interceptor_event);
		terminate = true;
	}
	return terminate;
}

bool wait_for_process_termination(process_intercepted* proc) {
	while (!verify_program_termination(proc)) {
		sleep_ms(1000);
	}
	sleep_ms(2000);
	return true;
}