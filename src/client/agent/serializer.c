#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "agent_protocol.h"
#include "agent_config.h"
#include "agent_utility.h"
#include "cJSON.h"
#include "mbedtls/base64.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/sha256.h"
#include "lz4.h"

static bool update_session_key(session* sess) {
	sess->session_key_iteration++;
	uint8_t* new_key = MEM_ALLOC(32);
	if (!new_key) goto fail;

	// change the session key according to the current iteration
	memcpy(sess->session_key, sess->original_session_key, 32);
	*((uint32_t*)sess->session_key) ^= sess->session_key_iteration;

	// compute the new session key
	if (mbedtls_sha256_ret(sess->session_key, 32, new_key, 0)) goto fail;
	memcpy(sess->session_key, new_key, 32);
	FREE(new_key);
	return true;
fail:
	if (new_key) free(new_key);
	return false;
}

static uint8_t* compute_server_session_key(session* sess, uint32_t iteration) {
	uint8_t tmp_key[32] = { 0 };
	uint8_t* server_key = MEM_ALLOC(32);
	if (!server_key) goto fail;

	// change the session key according to the server iteration
	memcpy(tmp_key, sess->original_session_key, 32);
	*((uint32_t*)tmp_key) ^= iteration;

	// compute the server session key	
	if (mbedtls_sha256_ret(tmp_key, 32, server_key, 0)) goto fail;
	
exit:
	return server_key;

fail:
	if (server_key) FREE(server_key);
	server_key = 0;
	goto exit;
}

bool message_deserialize(session* sess, message* msg, size_t serialized_data_size, uint8_t* serialized_data) {
	uint32_t data_size = serialized_data_size;
	uint8_t* data = MEM_ALLOC(data_size + 1);	
	if (!data) goto fail;
	memcpy(data, serialized_data, data_size);
	
	uint8_t* decrypted_data = ZERO(uint8_t);
	uint8_t* decoded_data = ZERO(uint8_t);
	uint8_t* decompressed_data = ZERO(uint8_t);

	cJSON* data_config = cJSON_GetObjectItemCaseSensitive(sess->config, CONFIG_DATA);
	if (data_config || !sess->is_established) {
		// check for encoding
		cJSON* jbase64_encode = cJSON_GetObjectItemCaseSensitive(data_config, CONFIG_DATA_BASE64ENCODE);
		if (!sess->is_established || (jbase64_encode && jbase64_encode->valueint)) {
			size_t olen = 0;
			decoded_data = base64_decode((char*)data, &olen);
			if (!decoded_data) goto fail;

			// copy the result back to data
			data_size = olen;
			data = realloc(data, data_size);
			if (!data) goto fail;
			memcpy(data, decoded_data, data_size);
			free(decoded_data);
			decoded_data = ZERO(uint8_t);
		}

		// check for encryption
		cJSON* encrypt = cJSON_GetObjectItemCaseSensitive(data_config, CONFIG_DATA_ENCRYPT);
		if (!sess->is_established || (encrypt && encrypt->valueint)) {	
			if (data_size < 36) goto fail;
			uint8_t* end_data = data + data_size;
			uint8_t* data_root = data;

			// extract sha256
			uint8_t input_sha256[32] = { 0 };
			memcpy(input_sha256, data, 32);
			data += sizeof(input_sha256);

			// compute session key
			uint32_t key_iteration = *((uint32_t*)data);
			data += sizeof(uint32_t);
			uint8_t* server_key = compute_server_session_key(sess, key_iteration);
			if (!server_key) goto fail;

			// decrypt data
			size_t enc_data_size = end_data - data;
			decrypted_data = MEM_ALLOC(enc_data_size);
			if (!decrypted_data) goto fail;

			uint8_t nonce[12] = { 0 };
			memcpy(nonce, sess->session_id, 12);
			if (mbedtls_chacha20_crypt(server_key, nonce, 0, enc_data_size, data, decrypted_data)) goto fail;
			FREE(server_key);

			// verify decrypted data integrity
			uint8_t sha256[32] = { 0 };
			if (mbedtls_sha256_ret(decrypted_data, enc_data_size, sha256, 0)) goto fail;
			if (memcmp(input_sha256, sha256, 32)) goto fail;

			// copy the result back to data
			data = realloc(data_root, enc_data_size);
			if (!data) goto fail;			
			data_size = enc_data_size;
			memcpy(data, decrypted_data, data_size);
			FREE(decrypted_data);
			decrypted_data = ZERO(uint8_t);
		}

		// check for compression
		cJSON* lz4_compress = cJSON_GetObjectItemCaseSensitive(data_config, CONFIG_DATA_LZ4COMPRESS);
		if (!sess->is_established || (lz4_compress && lz4_compress->valueint)) {
			// decompress the data
			size_t decompressed_size = *((uint32_t*)data);

			decompressed_data = MEM_ALLOC(decompressed_size);
			if (!decompressed_data) goto fail;
			if (!LZ4_decompress_fast(
				(char*)(data + sizeof(uint32_t)),
				(char*)decompressed_data,
				decompressed_size)
				) goto fail;

			// copy the result back to data			
			data = realloc(data, decompressed_size);
			if (!data) goto fail;
			memcpy(data, decompressed_data, decompressed_size);
			FREE(decompressed_data);
			decompressed_data = (uint8_t*){ 0 };
			data_size = decompressed_size;
		}
	}

	// decode the packets
	uint32_t offset = 0;
	packet* p = (packet*){ 0 };
	while (offset < data_size) {
		if (p) {
			p->next = OBJ_ALLOC(packet);
			if (!p->next) goto fail;
			p = p->next;
		}
		else {
			p = OBJ_ALLOC(packet);
			if (!p) goto fail;
			msg->response = p;
		}

		// decode packet
		p->id = *((uint32_t*)(data + offset));
		offset += sizeof(uint32_t);
		p->sequence = *((uint32_t*)(data + offset));
		offset += sizeof(uint32_t);
		p->data_type = *((uint32_t*)(data + offset));
		offset += sizeof(uint32_t);
		p->state = *((uint32_t*)(data + offset));
		offset += sizeof(uint32_t);
		p->data_size = *((uint32_t*)(data + offset));
		offset += sizeof(uint32_t);

		p->data = MEM_ALLOC(p->data_size);
		if (!p->data) goto fail;
		memcpy(p->data, data + offset, p->data_size);
		offset += p->data_size;
	}

	return true;

fail:
	FREE(decoded_data);
	FREE(decrypted_data);
	FREE(decompressed_data);
	return false;
}

bool message_serialize(session* sess, message* msg, size_t* serialized_data_size, uint8_t** serialized_data) {
	// check if there are any data to serialize
	*serialized_data = ZERO(uint8_t);
	*serialized_data_size = 0;
	if (!msg->request) return true;

	uint8_t* data = ZERO(uint8_t);
	uint8_t* compressed_data = ZERO(uint8_t);
	uint8_t* b64encoded_data = ZERO(uint8_t);
	uint8_t* encrypted_data = ZERO(uint8_t);

	// compute the total size
	uint32_t data_size = 0;
	packet* req = msg->request;
	while (req) {
		data_size += 
			req->data_size + 
			sizeof req->data_size + 
			sizeof req->data_type + 
			sizeof req->state +
			sizeof req->id +
			sizeof req->sequence;
		req = req->next;
	}

	// reserve space for sha256
	data_size += 32;

	// create serialized string
	data = MEM_ALLOC(data_size);
	if (!data) goto fail;
	uint32_t* pdata = (uint32_t*)data;

	// leave space for sha256 value
	pdata += 32 / sizeof(uint32_t);

	// copy all packet data
	req = msg->request;
	while (req) {
		*(uint32_t*)pdata++ = req->id;
		*(uint32_t*)pdata++ = req->sequence;
		*(uint32_t*)pdata++ = req->data_type;
		*(uint32_t*)pdata++ = req->state;
		*(uint32_t*)pdata++ = req->data_size;
		memcpy(pdata, req->data, req->data_size);
		req = req->next;
	}

	// compute and write sha256 hash of the data
	if (mbedtls_sha256_ret(data + 32, data_size - 32, data, 0)) goto fail;

	// data transformation
	cJSON* data_config = cJSON_GetObjectItemCaseSensitive(sess->config, CONFIG_DATA);
	
	// check for compression
	cJSON* lz4_compress = 
		data_config ?
		cJSON_GetObjectItemCaseSensitive(data_config, CONFIG_DATA_LZ4COMPRESS) :
		ZERO(cJSON);

	if (!sess->is_established || (lz4_compress && lz4_compress->valueint)) {
		// compress the data
		size_t compressed_size = LZ4_compressBound(data_size);
		compressed_data = MEM_ALLOC(compressed_size);
		if (!compressed_data) goto fail;
		compressed_size = LZ4_compress_default((char*)data, (char*)compressed_data, data_size, compressed_size);
		if (!compressed_size)  goto fail;

		// copy the result back to data			
		data = realloc(data, compressed_size + sizeof(uint32_t));
		if (!data) goto fail;
		*((uint32_t*)data) = data_size;
		memcpy(data + sizeof(uint32_t), compressed_data, compressed_size);
		data_size = compressed_size + sizeof(uint32_t);
		FREE(compressed_data);
		compressed_data = ZERO(uint8_t);
	}

	// check for encryption
	cJSON* encrypt = 
		data_config ?
		cJSON_GetObjectItemCaseSensitive(data_config, CONFIG_DATA_ENCRYPT) :
		ZERO(cJSON);

	if (!sess->is_established || (encrypt && encrypt->valueint)) {
		// update session key
		if (!update_session_key(sess)) goto fail;
		encrypted_data = MEM_ALLOC(data_size);
		if (!encrypted_data) goto fail;

		// compute sha256
		uint8_t sha256[32] = { 0 };
		if (mbedtls_sha256_ret(data, data_size, sha256, 0)) goto fail;
		
		// encrypt data
		uint8_t nonce[12] = { 0 };
		memcpy(nonce, sess->session_id, 12);
		if (mbedtls_chacha20_crypt(sess->session_key, nonce, 0, data_size, data, encrypted_data)) goto fail;

		// copy the sha256 value		
		data = realloc(data, data_size + sizeof(uint32_t) + sizeof(sha256));
		uint8_t* p_data = data;
		memcpy(p_data, sha256, sizeof(sha256));
		p_data += sizeof(sha256);

		// copy the session iteration
		*((uint32_t*)p_data) = sess->session_key_iteration;
		p_data += sizeof(uint32_t);

		// copy the encrypted data
		memcpy(p_data, encrypted_data, data_size);

		data_size += sizeof(uint32_t) + sizeof(sha256);
		FREE(encrypted_data);
		encrypted_data = ZERO(uint8_t);
	}

	// check for encoding
	cJSON* jbase64_encode = 
		data_config ?
		cJSON_GetObjectItemCaseSensitive(data_config, CONFIG_DATA_BASE64ENCODE) :
		ZERO(cJSON);

	if (!sess->is_established || (jbase64_encode && jbase64_encode->valueint)) {		
		b64encoded_data = (uint8_t*)base64_encode(data_size, data);
		if (!b64encoded_data) goto fail;

		// copy the result back to data
		data_size = strlen(b64encoded_data);
		data = realloc(data, data_size);
		if (!data) goto fail;
		memcpy(data, b64encoded_data, data_size);
		FREE(b64encoded_data);
		b64encoded_data = ZERO(uint8_t);
	}	

	*serialized_data_size = data_size;
	*serialized_data = data;
	return true;

fail:
	FREE(data);
	FREE(compressed_data);
	FREE(b64encoded_data);
	FREE(encrypted_data);
	*serialized_data = ZERO(uint8_t);
	*serialized_data_size = 0;
	return false;
}