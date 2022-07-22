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

extern void run(void);
extern void wait_thread(void);
extern HANDLE g_hTerminationEvent;

void wait_thread(void) {
	WaitForSingleObject(g_hTerminationEvent, INFINITE);
}

HRESULT __declspec(dllexport) DllRegisterServer(void) {
	wait_thread();
	return 0;
}

HRESULT __declspec(dllexport) DllUnregisterServer(void) {
	wait_thread();
	return 0;
}

bool __stdcall DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserver) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
#ifdef _WIN32	
		g_hTerminationEvent = CreateEvent(NULL, true, false, NULL);
		_beginthreadex(
			ZERO(void),
			0,
			(_beginthreadex_proc_type)run,
			NULL,
			0,
			ZERO(uint32_t)
		);
#else
#error Thread creation on non Windows platform is not supported
#endif
		// this condition is satisfied by the PE module loader, and allow it to 
		// run the main code without returning immediatly from the calling thread.
		if (lpReserver && GetCurrentProcessId() == (uint32_t)lpReserver) {
			// call the function to wait for the thread completation			
			wait_thread();
		}
	}
	return true;
}