#pragma once
#ifndef RUN_JS_H
#define RUN_JS_H

#include "quickjs.h"
#include "quickjs-libc.h"
//#include "storage/quickjs-storage.h"

int run_quickjs_file(char* filename);
int run_quickjs_code(char* encoded_buffer, char* filename);
#endif