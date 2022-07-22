#pragma once
#ifndef THREAD_H
#define THREAD_H
#include <stdbool.h>
#include <stdint.h>

// the thread routine interface
typedef unsigned(*thread_proc)(void*);

typedef struct thread_handle_s thread_handle;
struct thread_handle_s {
	uintptr_t handle;
	thread_proc thread_start;
};

// start a new thread
thread_handle* thread_start(thread_proc callback, void* args);

// check if the thread is alive
bool thread_is_alive(thread_handle* thread);

// kill a thread
bool thread_kill(thread_handle* thread);

// create a new thread handle
thread_handle* thread_new(uintptr_t handle);

// set the OS dependant thread handle
void thread_set_handle(thread_handle* thread, uintptr_t handle);

// free a thread handle
void thread_free(thread_handle* thread, bool kill_thread);

// wait for the given thread to terminate
void thread_wait(thread_handle* thread, uint32_t ms_timesout);

#endif