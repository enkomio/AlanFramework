#pragma once
#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include <stdbool.h>

bool rw_create_dir(const char* name);
char* get_directory(const char* name);

#endif