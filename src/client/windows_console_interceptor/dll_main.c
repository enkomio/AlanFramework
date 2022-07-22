#include <Windows.h>
#include <stdbool.h>
#include <process.h>
#include "agent_output_interceptor.h"
#include "agent_config.h"
#include "agent_utility.h"

static uintptr_t g_hThread = 0;

static void WINAPI interceptor_main(void) {
	interceptor_session_initialize();
	if (SUCCESS(interceptor_run())) {
		interceptor_wait_completation();
		interceptor_free();
	}
}

static void wait_thread(void) {
	WaitForSingleObject((HANDLE)g_hThread, INFINITE);
}

bool __stdcall DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserver) {
	if (fdwReason == DLL_PROCESS_ATTACH) {		
#ifdef _WIN32	
		g_hThread = _beginthreadex(
			ZERO(void),
			0,
			(_beginthreadex_proc_type)interceptor_main,
			ZERO(void),
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
	else if (fdwReason == DLL_PROCESS_DETACH) {
		interceptor_run_to_completation();
	}
	return true;
}