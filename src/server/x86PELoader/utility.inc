;
; Compute the hash of a buffer
; INPUT: ARG0: buffer ptr, ARG1: buffer length 
; RESULT: hash is saved in EAX
;
compute_hash proc
	push ebp
	mov ebp, esp

	push esi
	push ecx
	push edi
	push ebx
	push edx
	mov edx, 020h
	xor edi, edi

	mov esi, dword ptr [ebp+arg0]
	mov ecx, dword ptr [ebp+arg1]

@compute_hash_loop:	
	xor ebx, ebx
	lodsb byte ptr [esi]
	test al, al
	je @f

	ror edi, 13h
	cmp al, 'a'
	cmovge ebx, edx
	sub al, bl
	movzx eax, al
	add edi, eax
@@:
	loop @compute_hash_loop	
	
	mov eax, edi
	pop edx
	pop ebx
	pop edi
	pop ecx
	pop esi

	mov esp, ebp
	pop ebp
	ret 8
compute_hash endp

;
; Find the base address of a DLL given the hash name
; INPUT: ARG0: the DLL hash to identify
; OUTPUT: EAX the DLL base address or 0h if not found
;
find_lib_by_hash proc
	head EQU local0
	current_entry EQU local1
	string_buffer EQU local2

	push ebp
	mov ebp, esp
	sub esp, sizeof dword * 3

	assume fs:nothing
	mov eax, fs:[30h]  ; PEB
	assume fs:error

	; get head module list
	mov eax, [eax+0ch] ; Ldr
	mov eax, [eax+14h] ; InMemoryOrderModuleList entry
	mov [ebp+head], eax ; head
	mov [ebp+current_entry], eax ; cur entry

@find_module_loop:
	; get module name UNICODE_STRING FullDllName	
	lea ebx, [eax+1Ch]

	; find the last '/' character
	mov edi, (UNICODE_STRING ptr [ebx]).Buffer
	test edi, edi
	jz @lib_not_identified
	movzx ecx, (UNICODE_STRING ptr [ebx])._Length 
	add edi, ecx
	std ; scan backward

	; scan memory for char '\'
	xor eax, eax
	mov al, 5ch
	mov esi, edi
	repnz scasb
	cld
	jecxz @module_not_found

	add edi, 2
	mov [ebp+string_buffer], edi
	; compute module basename length
	sub esi, edi 

	; compute hash of the module base name
	push esi
	push edi
	call compute_hash
	
	; compare hash with the one that we want
	cmp eax, dword ptr [ebp+arg0]
	je @module_found
	
@module_not_found:
	mov eax, [ebp+current_entry]
	mov eax, [eax]
	mov [ebp+current_entry], eax
	cmp [ebp+head], eax
	jne @find_module_loop

@lib_not_identified:
	xor eax, eax
	jmp @exit

@module_found:
	mov eax, [ebp+current_entry]
	mov eax, [eax+10h] ; DllBase

@exit:
	mov esp, ebp
	pop ebp
	ret 4
find_lib_by_hash endp

;
; Find the exported function addres given the hash name
; INPUT: ARG0: the DLL base. ARG1: the function name hash to identify
; OUTPUT: return the function address or 0h if not found
;
find_func_by_hash proc
	dll_base equ arg0
	function_hash equ arg1
	edata_va equ local0
	current_index equ local1
	exported_function_count equ local2

	push ebp
	mov ebp, esp
	sub esp, sizeof dword * 3
	
	; check MZ signature
	mov ebx, dword ptr [ebp+dll_base]
	mov ax, word ptr [ebx]
	cmp ax, 'ZM'
	jnz @error

	; check PE signature
	mov ebx, dword ptr [ebx+03Ch]
	add ebx, dword ptr [ebp+dll_base]
	mov ax, word ptr [ebx]
	cmp ax, 'EP'
	jnz @error
	
	; get .edata VirtualAddress
	mov edx, dword ptr [ebx+078h] 
	test edx, edx
	jz @error
	add edx, dword ptr [ebp+dll_base]
	
	; init values
	xor eax, eax
	mov ecx, dword ptr [edx+014h]
	mov dword ptr [ebp+edata_va], edx
	mov dword ptr [ebp+current_index], eax	
	mov dword ptr [ebp+exported_function_count], ecx

@find_function_loop:
	; get the i-th function name
	mov edx, dword ptr [ebp+edata_va]
	mov esi, dword ptr [edx+020h] ; AddressOfNames RVA
	add esi, dword ptr [ebp+dll_base]
	mov ebx, dword ptr [ebp+current_index]
	lea esi, dword ptr [esi+sizeof dword * ebx]
	mov edi, dword ptr [esi]
	add edi, dword ptr [ebp+dll_base]
	
	; scan to find the NULL char
	xor eax, eax	
	mov esi, edi
	mov ecx, 512h
	cld
	repnz scasb

	; compute name length
	sub edi, esi
	dec edi

	; compute function name hash
	push edi
	push esi
	call compute_hash

	; compare hash
	cmp eax, [ebp+function_hash]
	je @function_name_found

	; go to next function
	inc dword ptr [ebp+current_index]
	mov ecx, [ebp+exported_function_count]
	loop @find_function_loop
	jmp @error

@function_name_found:
	; get the i-th function ordinal
	mov edx, [ebp+edata_va]
	mov esi, [edx+024h] ; AddressOfNameOrdinals RVA
	add esi, [ebp+dll_base]
	mov ebx, [ebp+current_index]
	lea esi, [esi+sizeof word * ebx]
	movzx eax, word ptr [esi]
		
	; get the i-th function address
	mov esi, [edx+01Ch] ; AddressOfFunctions RVA
	add esi, [ebp+dll_base]
	lea esi, [esi+sizeof dword * eax]
	mov eax, [esi]
	add eax, [ebp+dll_base]
	jmp @finish

@error:
	xor eax, eax
	
@finish:
	mov esp, ebp
	pop ebp
	ret 8
find_func_by_hash endp

;
; Call a given function by hash
; Input: EAX: hash function, ECX: lib base address, ARG0-N: function to call args
;
call_function macro
	push eax
	push ecx
	call find_func_by_hash
	call eax
endm