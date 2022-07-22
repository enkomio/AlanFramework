#ifdef _WIN32
#include <Windows.h>
#endif

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "str_builder.h"
#include "agent_config.h"
#include "agent_filesystem.h"
#include "agent_utility.h"

// from: https://nachtimwald.com/2017/05/17/recursive-create-directory-in-c/

static void str_split_free(char** in, size_t num_elm)
{
    if (in == NULL)
        return;
    if (num_elm != 0)
        free(in[0]);
    free(in);
}

static char** str_split(const char* in, size_t in_len, char delm, size_t* num_elm, size_t max)
{
    char* parsestr;
    char** out;
    size_t  cnt = 1;
    size_t  i;

    if (in == NULL || in_len == 0 || num_elm == NULL)
        return NULL;

    parsestr = malloc(in_len + 1);
    memcpy(parsestr, in, in_len + 1);
    parsestr[in_len] = '\0';

    *num_elm = 1;
    for (i = 0; i < in_len; i++) {
        if (parsestr[i] == delm)
            (*num_elm)++;
        if (max > 0 && *num_elm == max)
            break;
    }

    out = malloc(*num_elm * sizeof(*out));
    out[0] = parsestr;
    for (i = 0; i < in_len && cnt < *num_elm; i++) {
        if (parsestr[i] != delm)
            continue;

        /* Add the pointer to the array of elements */
        parsestr[i] = '\0';
        out[cnt] = parsestr + i + 1;
        cnt++;
    }

    return out;
}

bool rw_create_dir(const char* name)
{
    str_builder_t* sb;
    char** parts;
    size_t          num_parts;
    size_t          i;
    bool            ret = true;

    if (name == NULL || *name == '\0')
        return false;

    parts = str_split(name, strlen(name), DIRECTORY_SEPARATOR, &num_parts, 0);
    if (parts == NULL || num_parts == 0) {
        str_split_free(parts, num_parts);
        return false;
    }

    sb = str_builder_create();
    i = 0;
#ifdef _WIN32
    /* If the first part has a ':' it's a drive. E.g 'C:'. We don't
     * want to try creating it because we can't. We'll add it to base
     * and move forward. The next part will be a directory we need
     * to try creating. */
    if (strchr(parts[0], ':')) {
        i++;
        str_builder_add_str(sb, parts[0], strlen(parts[0]));
        str_builder_add_char(sb, DIRECTORY_SEPARATOR);
    }
#else
    if (*name == '/') {
        str_builder_add_char(sb, DIRECTORY_SEPARATOR);
    }
#endif

    for (; i < num_parts; i++) {
        if (parts[i] == NULL || *(parts[i]) == '\0') {
            continue;
        }

        str_builder_add_str(sb, parts[i], strlen(parts[i]));
        str_builder_add_char(sb, DIRECTORY_SEPARATOR);

#ifdef _WIN32
        if (CreateDirectory(str_builder_peek(sb), NULL) == FALSE) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                ret = false;
                goto done;
            }
        }
#else
        if (mkdir(str_builder_peek(sb), 0774) != 0)
            if (errno != EEXIST) {
                ret = false;
                goto done;
            }
#endif
    }

done:
    str_split_free(parts, num_parts);
    str_builder_destroy(sb);
    return ret;
}

char* get_directory(const char* name) {
    char* last_sep = name;
    char* name_ptr = name;
    char* directory = ZERO(char);

    while (*name_ptr++) {
        if (*name_ptr == DIRECTORY_SEPARATOR) {
            last_sep = name_ptr;
        }
    }

    size_t size = last_sep - name + 1;
    directory = MEM_ALLOC(size);
    if (!directory) return ZERO(char);

    memcpy(directory, name, size);
    return directory;
}