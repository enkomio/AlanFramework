
#include "agent_session.h"
#include "agent_protocol.h"
#include "cJSON.h"
#include "agent_utility.h"
#include "agent_config.h"
#include "agent_commands.h"

command_result* cmd_sleep(session* sess, packet* pck) {
	DECLARE_RESULT(error);
	cJSON* jpck= convert_to_JSON(pck);
	if (!jpck) goto exit;
	
	cJSON* jsession = cJSON_GetObjectItem(sess->config, CONFIG_SESSION);
	if (jsession) {
		// set sleep
		cJSON* input_sleep = cJSON_GetObjectItem(jpck, CONFIG_SESSION_SLEEP);
		if (input_sleep) {
			cJSON* config_sleep = cJSON_GetObjectItem(jsession, CONFIG_SESSION_SLEEP);
			if (config_sleep) {
				cJSON_SetIntValue(config_sleep, input_sleep->valueint);
			}
			else {
				config_sleep = cJSON_CreateNumber(input_sleep->valueint);
				cJSON_AddItemToObject(jsession, CONFIG_SESSION_SLEEP, config_sleep);
			}
		}
		
		// set jitter
		cJSON* input_jitter = cJSON_GetObjectItem(jpck, CONFIG_SESSION_JITTER);
		if (input_jitter) {
			cJSON* config_jitter = cJSON_GetObjectItem(jsession, CONFIG_SESSION_JITTER);
			if (config_jitter) {
				cJSON_SetIntValue(config_jitter, input_jitter->valueint);
			}
			else {
				config_jitter = cJSON_CreateNumber(input_jitter->valueint);
				cJSON_AddItemToObject(jsession, CONFIG_SESSION_JITTER, config_jitter);
			}
		}
	}

	SET_RESULT_SUCCESS(error);
exit:
	if (jpck) cJSON_Delete(jpck);
	return error;
}