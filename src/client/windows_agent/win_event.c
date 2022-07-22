#include <Windows.h>
#include <synchapi.h>
#include "agent_event.h"
#include "agent_utility.h"

struct event_handle_s {
	HANDLE handle;
};

event_handle* event_new(char* name) {
	event_handle* hEvent = OBJ_ALLOC(event_handle);
	if (!hEvent) goto fail;

	SECURITY_DESCRIPTOR sd = { 0 };
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, 0, FALSE);

	SECURITY_ATTRIBUTES securityAttributes = { 0 };
	securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	securityAttributes.lpSecurityDescriptor = NULL;
	securityAttributes.bInheritHandle = TRUE;
	securityAttributes.lpSecurityDescriptor = &sd;	

	hEvent->handle = CreateEvent(&securityAttributes, TRUE, FALSE, name);
	if (!hEvent->handle) goto fail;
	return hEvent;
fail:
	FREE(hEvent);
	return NULL;
}

event_handle* event_open(char* name) {
	event_handle* hEvent = OBJ_ALLOC(event_handle);
	if (!hEvent) goto fail;
	hEvent->handle = OpenEvent(EVENT_ALL_ACCESS, FALSE, name);
	if (!hEvent->handle) goto fail;
	return hEvent;
fail:
	FREE(hEvent);
	return NULL;
}

void event_free(event_handle* e) {
	if (e) {
		if (e->handle) CloseHandle(e->handle);
		FREE(e);
	}	
}

bool event_wait(event_handle* e, uint32_t timeout) {
	if (e && e->handle)
		return WAIT_OBJECT_0 == WaitForSingleObject(e->handle, timeout);
	return false;
}

bool event_set(event_handle* e) {
	if (e && e->handle) 
		return SetEvent(e->handle);
	return false;
}

bool event_is_signaled(event_handle* e) {
	return event_wait(e, 0);
}