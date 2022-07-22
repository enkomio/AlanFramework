#pragma once
#ifndef EVENT_H
#define EVENT_H
#include <stdbool.h>
#include <stdint.h>

typedef struct event_handle_s event_handle;

// create an event
event_handle* event_new(char* name);

// open a given event by its name
event_handle* event_open(char* name);

// free the created event
void event_free(event_handle* e);

// wait for the specified event
bool event_wait(event_handle* e, uint32_t timeout);

// set the specified event
bool event_set(event_handle* e);

// return true is the event is signaled, false otherwise
bool event_is_signaled(event_handle* e);

#endif