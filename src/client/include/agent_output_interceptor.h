#pragma once
#ifndef OUTPUT_INTERCEPTOR_H
#define OUTPUT_INTERCEPTOR_H

#include <stdint.h>
#include "agent_named_pipe.h"
#include "agent_event.h"

struct interceptor_s;
typedef struct interceptor_s interceptor;

bool interceptor_session_initialize(void);
uint32_t interceptor_run(void);
void interceptor_wait_completation(void);
bool interceptor_run_to_completation(void);
void interceptor_free(void);
#endif