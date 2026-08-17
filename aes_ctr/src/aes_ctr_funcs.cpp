#define EXTENSION_NAME aes_ctr
#define LIB_NAME "aes_ctr"
#define MODULE_NAME "aes_ctr"

#include <dmsdk/sdk.h>
#include <vector>
#include <cstdlib> 
#include <ctime>   
#include <cstdint>
#include <cmath>

#include "aes.h"
#include "sha.hpp"


static void secure_wipe(void* ptr, size_t size) 
{
	volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
	while (size--) {
		*p++ = 0;
	}
}

static bool read_byte_array_from_table(lua_State* L, int index, std::vector<uint8_t>& out_vector, size_t expected_size) 
{
	// check if not a table
	if (!lua_istable(L, index)) {
		// generate error string
		lua_pushfstring(L, "bad argument #%d (table expected, got %s)", index, luaL_typename(L, index));
		return false;
	}

	// check table length
	size_t table_len = lua_objlen(L, index);
	if (table_len != expected_size) {
		lua_pushfstring(L, "bad argument #%d (table length must be %d, got %d)", index, (int)expected_size, (int)table_len);
		return false;
	}

	out_vector.resize(expected_size);
	for (size_t i = 0; i < expected_size; ++i) {
		lua_rawgeti(L, index, i + 1);
		if (!lua_isnumber(L, -1)) {
			lua_pushfstring(L, "bad argument #%d (value at index %d is not a number, got %s)", index, (int)(i + 1), luaL_typename(L, -1));
			// remove the bad value we just read, leaving only the error string on the stack
			lua_remove(L, -2); 
			return false;
		}

		// mitigrate agains floating point creep
		double val = lua_tonumber(L, -1);
		double rounded = std::round(val);

		// check valid number
		if (std::fabs(val - rounded) > 0.0001 || rounded < 0 || rounded > 255) {
			lua_pushfstring(L, "bad argument #%d (value at index %d must be an integer between 0 and 255, got %f)", index, (int)(i + 1), val);
			// remove the bad value, leaving only the error string
			lua_remove(L, -2); 
			return false;
		}

		out_vector[i] = static_cast<uint8_t>(rounded);

		// pop the value off the stack after successfully reading
		lua_pop(L, 1);
	}
	return true;
}

static bool generate_key_from_seed(lua_State* L, int index, std::vector<uint8_t>& out_vector) {

	// ensure is string
	if (!lua_isstring(L, index)) {
		lua_pushfstring(L, "bad argument #%d (string expected, got %s)", index, luaL_typename(L, index));
		return false;
	}

	// get string 
	size_t seed_len;
	const char* seed_str = lua_tolstring(L, index, &seed_len);

	// check length
	if (seed_len == 0) {
		lua_pushfstring(L, "bad argument #%d (seed string cannot be empty)", index);
		return false;
	}

	// define a hardcoded app-specific salt vector to mix with the user seed.
	const uint8_t app_salt[] = { 0x58, 0x9A, 0x2C, 0xF1, 0x7E, 0x33, 0x0B, 0xE4 };

	// build an initial combined buffer: [User Seed + Salt + Length Marker]
	std::vector<uint8_t> buffer;
	buffer.reserve(seed_len + sizeof(app_salt) + 4);

	buffer.insert(buffer.end(), seed_str, seed_str + seed_len);
	buffer.insert(buffer.end(), app_salt, app_salt + sizeof(app_salt));

	// append the seed length as extra confusion bytes
	buffer.push_back(static_cast<uint8_t>(seed_len & 0xFF));
	buffer.push_back(static_cast<uint8_t>((seed_len >> 8) & 0xFF));

	// initial hash pass
	std::vector<uint8_t> current_hash = sha::compute(buffer, buffer.data(), buffer.size());

	// mess about with 
	for (int round = 0; round < 200; ++round) {
		std::vector<uint8_t> round_input;
		round_input.reserve(current_hash.size() + sizeof(app_salt) + 2);

		// feed the previous hash back in, mixed with salt and a round counter
		round_input.insert(round_input.end(), current_hash.begin(), current_hash.end());
		round_input.insert(round_input.end(), app_salt, app_salt + sizeof(app_salt));
		round_input.push_back(static_cast<uint8_t>(round & 0xFF));
		round_input.push_back(static_cast<uint8_t>((round >> 8) & 0xFF));

		current_hash = sha::compute(round_input, round_input.data(), round_input.size());
	}

	// output vector becomes our heavily mutated, stretched 32-byte key
	out_vector = current_hash;

	// wipe intermediate buffers from memory before returning
	secure_wipe(buffer.data(), buffer.size());

	return true;
}

static void generate_random_iv(std::vector<uint8_t>& iv) {
	iv.resize(16);

	// static counter ensures that even if called multiple times in the same second, the IV seed will be different,
	static unsigned int seed_counter = 0;
	if (seed_counter == 0) {
		srand((unsigned int)time(NULL));
	}
	seed_counter++;

	for (int i = 0; i < 16; ++i) {
		// mix rand() with the counter to ensure strict uniqueness
		iv[i] = (uint8_t)((rand() + seed_counter + i) % 256);
	}
}

static int encrypt_aes_ctr_key(lua_State* L) {

	size_t data_len;
	const char* data = luaL_checklstring(L, 1, &data_len);

	// if no data then return error
	if (data_len == 0) {
		return luaL_error(L, "Data cannot be empty.");
	}
	
	// read key from lua table
	std::vector<uint8_t> key;
	if (!read_byte_array_from_table(L, 2, key, 32)) {
		return lua_error(L); 
	}

	// generate IV
	std::vector<uint8_t> iv;
	generate_random_iv(iv); 

	const size_t iv_size = 16;
	const size_t checksum_size = 32; 

	// prevent size_t overflow when calculating the blob size
	if (data_len > SIZE_MAX - iv_size - checksum_size) {
		return luaL_error(L, "Data is too large to encrypt.");
	}

	std::vector<uint8_t> blob;
	blob.resize(iv_size + data_len + checksum_size);

	std::memcpy(blob.data(), iv.data(), iv_size);
	std::memcpy(blob.data() + iv_size, data, data_len);

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key.data(), iv.data());
	AES_CTR_xcrypt_buffer(&ctx, blob.data() + iv_size, data_len);

	std::vector<uint8_t> checksum = sha::compute(key, blob.data(), iv_size + data_len);
	std::memcpy(blob.data() + iv_size + data_len, checksum.data(), checksum_size);

	lua_pushlstring(L, (const char*)blob.data(), blob.size());

	// wipe data from memory
	secure_wipe(key.data(), key.size());
	secure_wipe(&ctx, sizeof(ctx));
	
	return 1;
}

static int decrypt_aes_ctr_key(lua_State* L) 
{
	size_t blob_len;
	const char* blob_data = luaL_checklstring(L, 1, &blob_len);

	// check if data string is too short
	if (blob_len < 48) {
		return luaL_error(L, "Invalid save data: blob too short.");
	}

	// check if technically there is no data
	if (blob_len == 48) {
		return luaL_error(L, "Invalid save data: blob contains no data.");
	}

	// read key
	std::vector<uint8_t> key;
	if (!read_byte_array_from_table(L, 2, key, 32)) {
		return lua_error(L); 
	}

	const size_t iv_size = 16;
	const size_t checksum_size = 32;
	size_t data_len = blob_len - iv_size - checksum_size;

	const uint8_t* iv_ptr = (const uint8_t*)blob_data;
	const uint8_t* data_ptr = iv_ptr + iv_size;
	const uint8_t* stored_checksum_ptr = data_ptr + data_len;

	std::vector<uint8_t> iv(iv_ptr, iv_ptr + iv_size);
	std::vector<uint8_t> data(data_ptr, data_ptr + data_len);

	if (!sha::verify(key, (const uint8_t*)blob_data,
	iv_size + data_len, stored_checksum_ptr)) {
		secure_wipe(key.data(), key.size());
		lua_pushnil(L);
		lua_pushstring(L, "Tamper check failed!");
		return 2;
	}

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key.data(), iv.data());
	AES_CTR_xcrypt_buffer(&ctx, data.data(), data.size());

	lua_pushlstring(L, (const char*)data.data(), data.size());

	// wipe data from memory
	secure_wipe(key.data(), key.size());
	secure_wipe(&ctx, sizeof(ctx));
	
	return 1;
}

static int encrypt_aes_ctr_seed(lua_State* L) {

	size_t data_len;
	const char* data = luaL_checklstring(L, 1, &data_len);

	// if no data then return error
	if (data_len == 0) {
		return luaL_error(L, "Data cannot be empty.");
	}

	std::vector<uint8_t> key;
	if (!generate_key_from_seed(L, 2, key)) {
		return lua_error(L); 
	}

	std::vector<uint8_t> iv;
	generate_random_iv(iv); 

	const size_t iv_size = 16;
	const size_t checksum_size = 32; 

	// Prevent size_t overflow when calculating the blob size
	if (data_len > SIZE_MAX - iv_size - checksum_size) {
		return luaL_error(L, "Data is too large to encrypt.");
	}

	std::vector<uint8_t> blob;
	blob.resize(iv_size + data_len + checksum_size);

	std::memcpy(blob.data(), iv.data(), iv_size);
	std::memcpy(blob.data() + iv_size, data, data_len);

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key.data(), iv.data());
	AES_CTR_xcrypt_buffer(&ctx, blob.data() + iv_size, data_len);

	std::vector<uint8_t> checksum = sha::compute(key, blob.data(), iv_size + data_len);
	std::memcpy(blob.data() + iv_size + data_len, checksum.data(), checksum_size);

	lua_pushlstring(L, (const char*)blob.data(), blob.size());

	// wipe data from memory
	secure_wipe(key.data(), key.size());
	secure_wipe(&ctx, sizeof(ctx));
	return 1;
}

static int decrypt_aes_ctr_seed(lua_State* L) 
{
	size_t blob_len;
	const char* blob_data = luaL_checklstring(L, 1, &blob_len);

	// check if data string is too short
	if (blob_len < 48) {
		return luaL_error(L, "Invalid save data: blob too short.");
	}

	// check if technically there is no data
	if (blob_len == 48) {
		return luaL_error(L, "Invalid save data: blob contains no data.");
	}

	// read key
	std::vector<uint8_t> key;
	if (!generate_key_from_seed(L, 2, key)) {
		return lua_error(L); 
	}

	const size_t iv_size = 16;
	const size_t checksum_size = 32;
	size_t data_len = blob_len - iv_size - checksum_size;

	const uint8_t* iv_ptr = (const uint8_t*)blob_data;
	const uint8_t* data_ptr = iv_ptr + iv_size;
	const uint8_t* stored_checksum_ptr = data_ptr + data_len;

	std::vector<uint8_t> iv(iv_ptr, iv_ptr + iv_size);
	std::vector<uint8_t> data(data_ptr, data_ptr + data_len);

	if (!sha::verify(key, (const uint8_t*)blob_data,
	iv_size + data_len, stored_checksum_ptr)) {
		secure_wipe(key.data(), key.size());
		lua_pushnil(L);
		lua_pushstring(L, "Tamper check failed!");
		return 2;
	}

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key.data(), iv.data());
	AES_CTR_xcrypt_buffer(&ctx, data.data(), data.size());

	lua_pushlstring(L, (const char*)data.data(), data.size());

	// wipe data from memory
	secure_wipe(key.data(), key.size());
	secure_wipe(&ctx, sizeof(ctx));

	return 1;
}

static const luaL_reg Module_methods[] = {
	{"encrypt_using_key", encrypt_aes_ctr_key},
	{"decrypt_using_key", decrypt_aes_ctr_key},     
	{"encrypt_using_seed", encrypt_aes_ctr_seed},
	{"decrypt_using_seed", decrypt_aes_ctr_seed},   
	{0, 0}
};

static void LuaInit(lua_State* L) {
	int top = lua_gettop(L);
	luaL_register(L, MODULE_NAME, Module_methods);
	lua_pop(L, 1);
}

static dmExtension::Result AppInitializeSecureString(dmExtension::AppParams* params) { return dmExtension::RESULT_OK; }
static dmExtension::Result InitializeSecureString(dmExtension::Params* params) {
	LuaInit(params->m_L);
	return dmExtension::RESULT_OK;
}
static dmExtension::Result AppFinalizeSecureString(dmExtension::AppParams* params) { return dmExtension::RESULT_OK; }
static dmExtension::Result FinalizeSecureString(dmExtension::Params* params) { return dmExtension::RESULT_OK; }

DM_DECLARE_EXTENSION(EXTENSION_NAME, LIB_NAME, AppInitializeSecureString, AppFinalizeSecureString, InitializeSecureString, 0, 0, FinalizeSecureString)