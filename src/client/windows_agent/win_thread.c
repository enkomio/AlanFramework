#include <Windows.h>
#include <stdint.h>
#include <process.h>
#include "agent_thread.h"
#include "agent_utility.h"

thread_handle* thread_start(thread_proc callback, void* args) {
    thread_handle* thread = OBJ_ALLOC(thread_handle);
    if (!thread) return ZERO(thread_handle);
    thread->thread_start = callback;

#ifdef _WIN32	
    thread->handle = _beginthreadex(
        NULL,
        0,
        (_beginthreadex_proc_type)callback,
        args,
        0,
        NULL
    );
#else
#error Thread creation on non Windows platform is not supported
#endif
    return thread;
}

bool thread_is_alive(thread_handle* thread) {
    return WaitForSingleObject((HANDLE)thread->handle, 0) == WAIT_TIMEOUT;
}

bool thread_kill(thread_handle* thread) {
    if (thread && thread->handle)
        return TerminateThread((HANDLE)thread->handle, 1);
    return false;
}

thread_handle* thread_new(uintptr_t handle) {
    thread_handle* thread = OBJ_ALLOC(thread_handle);
    if (!thread) return ZERO(thread_handle);
    thread->handle = handle;
    return thread;
}

void thread_set_handle(thread_handle* thread, uintptr_t handle) {
    thread->handle = handle;
}

void thread_free(thread_handle* thread, bool kill_thread) {
    if (thread && thread->handle) {
        if (kill_thread) {
            CancelSynchronousIo((HANDLE)thread->handle);
            // wait for thread termination
            if (WaitForSingleObject((HANDLE)thread->handle, 5 * 1000) == WAIT_TIMEOUT)
                thread_kill(thread);
        }        
        CloseHandle((HANDLE)thread->handle);
        thread->handle = 0;
    }        
    FREE(thread);
}

void thread_wait(thread_handle* thread, uint32_t ms_timesout)
{
    if (thread && thread->handle) {
        if (thread_is_alive(thread))
            WaitForSingleObject((HANDLE)thread->handle, ms_timesout);
    }
}