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
#include "agent_utility.h"

extern void win_main(void*);

int WinMain(
    HINSTANCE   hInstance,
    HINSTANCE   hPrevInstance,
    LPSTR       lpCmdLine,
    int         nCmdShow
) { 
	HMODULE hModule = GetModuleHandle(NULL);	
#ifdef _WIN32	
	uintptr_t hThread = _beginthreadex(
		ZERO(void),
		0,
		(_beginthreadex_proc_type)win_main,
		hModule,
		0,
		ZERO(uint32_t)
	);
	if (!hThread) goto fail;
	WaitForSingleObject((HANDLE)hThread, INFINITE);
	return EXIT_SUCCESS;
#else
#error Thread creation on non Windows platform is not supported
#endif

fail:
	return EXIT_FAILURE;
}