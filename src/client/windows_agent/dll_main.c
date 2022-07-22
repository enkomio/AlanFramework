#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <libloaderapi.h>
#include <processthreadsapi.h>
#include <process.h>
#include <stddef.h>
#include <synchapi.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "agent_utility.h"

uintptr_t g_hThread = 0;
extern void win_main(void*);

static void wait_thread(void) {
	WaitForSingleObject((HANDLE)g_hThread, INFINITE);
}

bool __stdcall DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserver) 
{
	if (fdwReason == DLL_PROCESS_ATTACH) {
#ifdef _WIN32	
		g_hThread = _beginthreadex(
			ZERO(void),
			0,
			(_beginthreadex_proc_type)win_main,
			(void*)hModule,
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