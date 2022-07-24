;
; Compute the hash of a buffer
; INPUT: ARG0: buffer ptr, ARG1: buffer length 
; RESULT: hash is returned
;
compute_hash proc frame
	alloc_stack(sizeof STD_FUNCTION_STACK_MICRO)
	SAVE_ALL_STD_REGS STD_FUNCTION_STACK_MICRO
.endprolog

	; initialize
	mov rsi, rcx ; RSI = buffer
	mov rcx, rdx ; RCX = buffer size

	mov rdx, 020h
	xor rdi, rdi

@compute_hash_loop:	
	xor rbx, rbx
	lodsb byte ptr [rsi]
	test al, al
	je @f

	ror edi, 13h
	cmp al, 'a'
	cmovge rbx, rdx
	sub al, bl
	movzx rax, al
	add edi, eax
@@:
	loop @compute_hash_loop	
	
	mov rax, rdi
	RESTORE_ALL_STD_REGS STD_FUNCTION_STACK_MICRO
	add rsp, sizeof STD_FUNCTION_STACK_MICRO
	ret
compute_hash endp

;
; Find the base address of a DLL given the hash name
; INPUT: ARG0: the DLL hash to identify
; OUTPUT: the DLL base address or 0h if not found
;
find_lib_by_hash proc frame
	alloc_stack(sizeof STD_FUNCTION_STACK_MICRO)
	SAVE_ALL_STD_REGS STD_FUNCTION_STACK_MICRO
.endprolog

	mov STD_FUNCTION_STACK_MICRO.Parameters.Param1[rsp], rcx ; hash to identify

	; get PEB 
	; http://terminus.rewolf.pl/terminus/structures/ntdll/_TEB64_x64.html	
	; http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_x64.html
	mov rax, gs:[60h]

	; get head module list
	mov rax, [rax+18h] ; Ldr
	mov rax, [rax+20h] ; InMemoryOrderModuleList entry
	mov STD_FUNCTION_STACK_MICRO.Parameters.Param2[rsp], rax ; head
	mov STD_FUNCTION_STACK_MICRO.Parameters.Param3[rsp], rax ; cur entry

@find_module_loop:
	; get module name UNICODE_STRING FullDllName	
	; http://terminus.rewolf.pl/terminus/structures/ntdll/_LDR_DATA_TABLE_ENTRY_x64.html
	lea rbx, [rax+38h]

	; find the last '/' character
	mov rdi, (UNICODE_STRING ptr [rbx]).Buffer
	test rdi, rdi
	jz @lib_not_identified
	movzx rcx, (UNICODE_STRING ptr [rbx])._Length 
	add rdi, rcx
	std ; scan backward

	; scan memory for char '\'
	xor rax, rax
	mov al, 5ch
	mov rsi, rdi
	repnz scasb
	cld
	jecxz @module_not_found

	; skip directory separator
	add rdi, 2

	; compute module basename length
	sub rsi, rdi 

	; compute hash of the module base name
	mov rdx, rsi
	mov rcx, rdi
	call compute_hash
	
	; compare hash with the one that we want
	cmp rax, STD_FUNCTION_STACK_MICRO.Parameters.Param1[rsp]
	je @module_found
	
@module_not_found:
	mov rax, STD_FUNCTION_STACK_MICRO.Parameters.Param3[rsp]
	mov rax, [rax]
	mov STD_FUNCTION_STACK_MICRO.Parameters.Param3[rsp], rax
	cmp STD_FUNCTION_STACK_MICRO.Parameters.Param2[rsp], rax
	jne @find_module_loop

 @lib_not_identified:
	xor rax, rax
	jmp @exit

@module_found:
	mov rax, STD_FUNCTION_STACK_MICRO.Parameters.Param3[rsp]
	mov rax, [rax+20h] ; DllBase

@exit:
	RESTORE_ALL_STD_REGS STD_FUNCTION_STACK_MICRO
	add rsp, sizeof STD_FUNCTION_STACK_MICRO
	ret
find_lib_by_hash endp

;
; Find the exported function addres given the hash name
; INPUT: ARG0: the DLL base. ARG1: the function name hash to identify
; OUTPUT: return the function address or 0h if not found
;
find_func_by_hash proc frame
	alloc_stack(sizeof STD_FUNCTION_STACK_MICRO)
	SAVE_ALL_STD_REGS STD_FUNCTION_STACK_MICRO
.endprolog
	
	mov STD_FUNCTION_STACK_MICRO.Parameters.Param1[rsp], rcx ; DLL base address
	mov STD_FUNCTION_STACK_MICRO.Parameters.Param2[rsp], rdx ; function name hash

	; check MZ signature	
	mov ax, word ptr [rcx]
	cmp ax, 'ZM'
	jnz @error

	; check PE signature
	mov ebx, dword ptr [rcx+03Ch]
	add rbx, rcx
	mov ax, word ptr [rbx]
	cmp ax, 'EP'
	jnz @error

	; get .edata VirtualAddress
	mov eax, dword ptr [rbx+088h] 
	test rax, rax
	jz @error
	add rax, rcx 
	
	; init values
	mov r12d, dword ptr [rax+014h] ; NumberOfNames
	mov r13, rax ; IMAGE_EXPORT_DIRECTORY	
	xor r14, r14 ; loop counter
	mov ebx, dword ptr [r13+020h]
	add rbx, rcx ; AddressOfNames VA	

@find_function_loop:
	; get the i-th function name
	lea rsi, dword ptr [rbx + r14 * sizeof dword]
	mov esi, dword ptr [rsi]
	add rsi, STD_FUNCTION_STACK_MICRO.Parameters.Param1[rsp]
		
	; scan to find the NULL char
	xor rax, rax	
	mov rdi, rsi
	mov ecx, 512h ; MAXPATH
	cld
	repnz scasb

	; compute function name length
	sub rdi, rsi
	dec rdi

	; compute function name hash
	mov rcx, rsi
	mov rdx, rdi
	call compute_hash

	; compare hash
	cmp rax, STD_FUNCTION_STACK_MICRO.Parameters.Param2[rsp]
	je @function_name_found

	; go to next function
	inc r14
	cmp r14, r12
	jnz @find_function_loop
	jmp @error

@function_name_found:
	; get the i-th function ordinal
	mov esi, [r13+024h] ; AddressOfNameOrdinals RVA
	add rsi, STD_FUNCTION_STACK_MICRO.Parameters.Param1[rsp] ; AddressOfNameOrdinals VA
	movzx rax, word ptr [rsi+sizeof word * r14]
		
	; get the i-th function address from the ordinal
	mov esi, [r13+01ch] ; AddressOfFunctions RVA
	add rsi, STD_FUNCTION_STACK_MICRO.Parameters.Param1[rsp] ; AddressOfFunctions VA
	mov eax, dword ptr [rsi+sizeof dword * r14]
	add rax, STD_FUNCTION_STACK_MICRO.Parameters.Param1[rsp] ; function address

	jmp @finish

@error:
	xor rax, rax
	
@finish:
	RESTORE_ALL_STD_REGS STD_FUNCTION_STACK_MICRO
	add rsp, sizeof STD_FUNCTION_STACK_MICRO
	ret
find_func_by_hash endp