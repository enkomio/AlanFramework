#include "agent_config.h"
#include "agent_protocol.h"
#include "agent_commands.h"
#include "agent_utility.h"

extern bool get_system_info(session* sess, packet* pck);
extern bool get_extended_system_info(session* sess, packet* pck);

command_result* cmd_systeminfo(session* sess, packet* pck) {
	DECLARE_RESULT_WITH_FEEDBACK(cmd_result);
	if (get_system_info(sess, pck))
		SET_RESULT_SUCCESS(cmd_result);
	return cmd_result;
}

command_result* cmd_extended_systeminfo(session* sess, packet* pck) {
	DECLARE_RESULT_WITH_FEEDBACK(cmd_result);
	cmd_result->error_code = ERROR_UNKNOWN;
	if (get_extended_system_info(sess, pck))
		SET_RESULT_SUCCESS(cmd_result);
	return cmd_result;
}