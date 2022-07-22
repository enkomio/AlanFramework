#include "agent_session.h"
#include "agent_protocol.h"
#include "cJSON.h"
#include "agent_utility.h"
#include "agent_config.h"
#include "agent_commands.h"

command_result* cmd_kill(session* sess, packet* pck) {
	DECLARE_RESULT(error);
	cJSON* jpck = convert_to_JSON(pck);
	if (!jpck) goto exit;

	cJSON* jpid = cJSON_GetObjectItem(jpck, KILL_PID);
	if (!jpid) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto exit;
	}
	if (process_kill(jpid->valueint)) {
		error->send_result = true;
		SET_RESULT_SUCCESS(error);
	}
		
exit:
	if (jpck) cJSON_Delete(jpck);
	return error;
}