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
extern HANDLE g_hTerminationEvent;

int WinMain(
	HINSTANCE   hInstance,
	HINSTANCE   hPrevInstance,
	LPSTR       lpCmdLine,
	int         nCmdShow
) {
	g_hTerminationEvent = CreateEvent(NULL, true, false, NULL);
	run();
	return 0;
}