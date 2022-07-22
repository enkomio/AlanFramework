#pragma once
#ifndef PROTOCOL_H
#define PROTOCOL_H
#include <stdint.h>
#include <stdbool.h>
#include "cJSON.h"
#include "agent_session.h"

// specify that the server shouldn't expect more data related to the given command
#define PACKET_STATE_NO_MORE_PACKETS 0
// specify that there will be more packet related to the specified command
#define PACKET_STATE_MORE_PACKETS 1

typedef struct packet_s packet;
struct packet_s {	
	// the ID of the command which this packet belong to
	uint32_t id;
	// a sequence number to identify the order in case of multiple packets
	uint32_t sequence;
	// the type of packet, see Request Type in agent_config.h
	uint32_t data_type;
	// provide metadata information on the packet. The possible value are 
	// PACKET_STATE_NO_MORE_PACKETS and PACKET_STATE_MORE_PACKETS
	uint32_t state;	
	uint32_t data_size;
	void* data;	
	packet* next;
};

typedef struct message_s message;
struct message_s {
	uint32_t session_id_size;
	char* session_id;
	packet* request;
	packet* response;
};


message* message_create(session* sess);
message* message_free(message* msg);
bool message_add_request_data(message* msg, size_t data_size, void* data, uint32_t id, uint32_t seq, uint32_t data_type, uint32_t state, bool force_add);
bool message_send(session* sess, message* msg);
bool message_send_command_result(session* sess, packet* pck, char* result_string);

// send data to the server and inform the server that no more data will be sent
bool message_send_data(session* sess, packet* pck, size_t buf_size, uint8_t* buffer);

// send data to the server and inform the server that there is more data to be sent
bool message_send_data_partial(session* sess, packet* pck, size_t buf_size, uint8_t* buffer);

// this function clone the given packet.
packet* message_clone_packet(packet* pck);

// free the packet
void message_packet_free(packet* pck);

#endif