comment !
x86 PE Loader, (c) Antonio 's4tan' Parata 2021
!

.686
.model flat, stdcall
.stack 4096

.data

Kernel32_hash equ 045a266c9h
Kernelbase_hash equ 07d33bb31h
msvcrt_hash equ 0cefaaaf3h
LoadLibraryA_hash equ 0b583c684h
GetProcAddress_hash equ 08ac5a822h
VirtualAlloc_hash equ 0e6959c02h
VirtualFree_hash equ 0f5fe5722h
VirtualQuery_hash equ 0cb960098h
FlushInstructionCache_hash equ 03aa03770h

.code

; this is necessary to jump to the correct EIP 
; when the .text section is copied
start proc
	jmp main
start endp

; clean-up shellcode args: 
;	- VirtualFree address
;	- base region addr
;	- region size
;	- OEP addr
@cleanup_shellcode_addr:
	call @f
@@: pop esi
	add esi, 5
	ret

@cleanup_shellcode: 	
	; overwirte memory with 0 for security reason
	pop ebx ; VirtualFree
	pop edi ; region addr	
	pop ecx ; region size
	pop edx ; OEP
	xor eax, eax	
	
	push edi ; save value
	push ecx ; save value

	; fill with 0
	rep stosb

	pop ecx ; restore value
	pop edi ; restore value

	; move to non-volatile register
	mov esi, edx

	; call VirtualFree and jump to OEP
	push 08000h ; dwFreeType: MEM_RELEASE
	push 0h ; dwSize
	push edi ; lpAddress
	call ebx ; call VirtualFree

	; call the OEP
	call esi
	mov esp, ebp
	pop ebp
	ret
cleanup_shellcode_size equ $ - @cleanup_shellcode

include <def.inc>
include <utility.inc>

;
; this is a PIC code that searches for a PE file after its code,
; load it in memory and run the entry-point
;
main proc
	push ebp
	mov ebp, esp

	; locals
	Kernel32_base equ local0
	LoadLibraryA_ptr equ local1
	GetProcAddress_ptr equ local2
	VirtualAlloc_ptr equ local3
	FlushInstructionCache_ptr equ local4
	MZ equ local5
	PE equ local6
	ImageBase equ local7
	saved_edi equ local8
	saved_esi equ local9
	saved_ebx equ local10
		
	; space for local vars and save non volatile registers
	sub esp, sizeof dword * 11
	mov dword ptr [ebp+saved_edi], edi
	mov dword ptr [ebp+saved_esi], esi
	mov dword ptr [ebp+saved_ebx], ebx

	; *****************************************************************
	; * step 0 - find Kernel32 base address and load needed functions *
	; *****************************************************************
	push Kernel32_hash
	call find_lib_by_hash	
	mov dword ptr [ebp+Kernel32_base], eax

	call @f
	; function hashes to be resolved
@function_hashes:
	dword Kernel32_hash
	dword LoadLibraryA_hash
	dword GetProcAddress_hash
	dword VirtualAlloc_hash
	dword FlushInstructionCache_hash	
@@:
	mov ecx, (($ - @function_hashes) / sizeof dword) - 1

@load_functions:	
	pop esi
	push esi
	lea esi, dword ptr [esi + sizeof dword * ecx]
	push ecx

	; find function address
	push dword ptr [esi]
	push dword ptr [ebp+Kernel32_base]	
	call find_func_by_hash	
	pop ecx	

	; save function pointer	
	lea edi, dword ptr [ebp+Kernel32_base]
	lea ebx, dword ptr [sizeof dword * ecx]
	sub edi, ebx
	mov dword ptr [edi], eax
	loop @load_functions

	pop esi
		
	; ******************************
	; * step 1 - find PE in memory *
	; ******************************
@search_payload:
	inc esi
	cmp word ptr [esi], 'ZM'
	jne @search_payload
	mov dword ptr [ebp+MZ], esi
	lea eax, dword ptr [esi+03ch]
	mov eax, dword ptr [eax]
	; safety check to avoid potential access violation
	cmp eax, 500h
	ja @search_payload
	lea eax, dword ptr [esi+eax]
	cmp word ptr [eax], 'EP'
	jne @search_payload
	mov dword ptr [ebp+PE], eax

	; ******************************************
	; * step 2 - change command-line arguments *
	; ******************************************
	push esi ; save value

	; get the the command-line size
	mov esi, dword ptr [ebp+MZ]
	lea esi, dword ptr [esi-4]
	cmp dword ptr [esi], 0h
	je @command_line_change_end

	; allocated memory for command-line
	push 040h; PAGE_EXECUTE_READWRITE
	push 03000h; MEM_RESERVE|MEM_COMMIT
	push dword ptr [esi]
	push 0h
	call dword ptr [ebp+VirtualAlloc_ptr]
	test eax, eax
	jz @error

	; copy the command-line to the newly allocated memory
	mov ecx, dword ptr [esi]
	mov ebx, ecx ; save value
	mov edi, eax
	sub esi, dword ptr [esi]
	rep movsb
	mov ecx, ebx ; restore value

	; change PEB->ProcessParameters CommandLine and ImagePathName
	assume fs:nothing
	mov ebx, fs:[30h]  ; PEB
	assume fs:error
	mov ebx, dword ptr [ebx+10h]
	lea ebx, (RTL_USER_PROCESS_PARAMETERS ptr [ebx]).CommandLine

	mov (UNICODE_STRING ptr [ebx])._Length, cx
	add cx, sizeof word
	mov (UNICODE_STRING ptr [ebx]).MaximumLength, cx
	mov (UNICODE_STRING ptr [ebx]).Buffer, eax

	; invoke again Kernelbase entry-point to invalidate cache from GetCommandLine(A|W)
	push Kernelbase_hash
	call find_lib_by_hash	
	test eax, eax
	jz @error
	lea esi, dword ptr [eax+03ch]
	mov esi, dword ptr [esi]
	add esi, eax ; PE

	mov esi, dword ptr [esi+28h] ; Kernelbase AddressOfEntryPoint	
	add esi, eax

	push 0h ; lpReserved 
	push 1h ; fdwReason
	push eax ; hinstDLL
	call esi

	; invoke again msvcrt entry-point to invalidate cache for __argv
	push msvcrt_hash
	call find_lib_by_hash	
	test eax, eax
	jz @load_msvcrt
	lea esi, qword ptr [eax+03ch]
	mov esi, dword ptr [esi]
	add esi, eax ; PE

	mov esi, dword ptr [esi+28h] ; msvcrt AddressOfEntryPoint	
	add esi, eax
		
	push 0h ; lpReserved 
	push 1h ; fdwReason
	push eax ; hinstDLL
	call esi
	jmp @command_line_change_end

@load_msvcrt:
	; msvcrt is not loaded, load it before time
	push 000007472h
	push 6376736dh
	push esp
	call dword ptr [ebp+LoadLibraryA_ptr]
	add esp, 2 * sizeof dword
@command_line_change_end:
	pop esi; restore value

	; **********************************
	; * step 3 - allocate space for PE *
	; **********************************
	mov eax, dword ptr [ebp+PE]
	mov edx, dword ptr [eax+050h]
	push 040h; PAGE_EXECUTE_READWRITE
	push 03000h; MEM_RESERVE|MEM_COMMIT
	push edx
	push 0h
	call dword ptr [ebp+VirtualAlloc_ptr]
	mov dword ptr [ebp+ImageBase], eax

	; ***************************
	; * step 4 - copy PE header *
	; ***************************
	mov ecx, dword ptr [ebp+PE]
	add ecx, 054h
	mov ecx, dword ptr [ecx]
	mov edi, dword ptr [ebp+ImageBase]
	rep movsb

	; **************************
	; * step 5 - copy sections *
	; **************************
	mov eax, dword ptr [ebp+PE]
	lea ebx, dword ptr [eax+6h] ; NumberOfSections
	movzx ebx, word ptr [ebx]
	add eax, 14h ; SizeOfOptionalHeaders
	movzx eax, word ptr [eax]
	mov edx, dword ptr [ebp+PE]
	add edx, 018h ; size of PE header + PE signature
	add edx, eax
@map_section:	
	lea edi, dword ptr [edx+0ch] ; VirtualAddress
	mov edi, dword ptr [edi]
	add edi, dword ptr [ebp+ImageBase]
	lea ecx, dword ptr [edx+10h] ; SizeOfRawData
	mov ecx, dword ptr [ecx]
	lea esi, dword ptr [edx+14h] ; PointerToRawData
	mov esi, dword ptr [esi]
	add esi, dword ptr [ebp+MZ]	
	rep movsb	
	add edx, 28h ; got next section
	dec ebx
	jne @map_section

	; *******************************
	; * step 6 - resolve PE imports *
	; *******************************
	mov esi, dword ptr [ebp+PE]
	lea esi, dword ptr [esi+080h] ; .idata rva
	mov esi, dword ptr [esi]
	test esi, esi
	jz @f
	add esi, dword ptr [ebp+ImageBase]

@resolve_PE_import:
	; load DLL
	mov eax, (IMAGE_IMPORT_DESCRIPTOR ptr [esi])._Name	
	test eax, eax
	jz @completed_resolve_PE_import
	add eax, dword ptr [ebp+ImageBase]
	push eax
	call dword ptr [ebp+LoadLibraryA_ptr]
	mov ebx, eax
		
	; save value
	push esi

	; resolve FirstThunk
	mov edi, (IMAGE_IMPORT_DESCRIPTOR ptr [esi]).FirstThunk	
	add edi, dword ptr [ebp+ImageBase]

	; resolve OriginalFirstThunk
	mov esi, (IMAGE_IMPORT_DESCRIPTOR ptr [esi]).OriginalFirstThunk
	add esi, dword ptr [ebp+ImageBase]
	
	; get DLL export data 
	mov edx, dword ptr [ebx+03ch]
	lea edx, dword ptr [edx+ebx+78h]
	mov edx, dword ptr [edx]
	add edx, ebx
	mov ecx, (IMAGE_EXPORT_DIRECTORY ptr [edx]).AddressOfFunctions 
	add ecx, ebx

@resolve_import:
	cmp dword ptr [esi], 0h
	je @resolve_next_DLL

	test (IMAGE_THUNK_DATA32 ptr [esi]).Ordinal, IMAGE_ORDINAL_FLAG32
	jz @resolve_import_by_names

	; resolve by ordinal
	mov eax, (IMAGE_THUNK_DATA32 ptr [esi]).Ordinal
	and eax, 0ffffh
	jmp @resolve_function_address

	; resolve functions by name
@resolve_import_by_names:

	; load function address 
	mov eax, (IMAGE_THUNK_DATA32 ptr [esi]).AddressOfData
	add eax, dword ptr [ebp+ImageBase]
	lea eax, (IMAGE_IMPORT_BY_NAME ptr [eax])._Name
	
@resolve_function_address:
	; save value
	push edx

	push eax
	push ebx	
	call dword ptr [ebp+GetProcAddress_ptr]
	
	; restore value
	pop edx

@write_function_address:
	mov (IMAGE_THUNK_DATA32 ptr [edi]).Function, eax
	cmp dword ptr [esi], 0h
	jz @f
	add esi, sizeof dword
@@:
	add edi, sizeof dword
	jmp @resolve_import

@resolve_next_DLL:
	pop esi
	add esi, sizeof IMAGE_IMPORT_DESCRIPTOR 
	jmp @resolve_PE_import
@completed_resolve_PE_import:

	; ***************************************
	; * step 7 - resolve delayed PE imports *
	; ***************************************
	mov esi, dword ptr [ebp+PE]
	mov esi, dword ptr [esi+0e0h] ; delay import rva
	test esi, esi
	jz @completed_resolve_delayed_PE_import
	add esi, dword ptr [ebp+ImageBase]

@resolve_delayed_PE_import:
	; load DLL
	mov eax, (IMAGE_DELAYLOAD_DESCRIPTOR ptr [esi]).DllNameRVA	
	test eax, eax
	jz @completed_resolve_delayed_PE_import
	add eax, dword ptr [ebp+ImageBase]
	push eax
	call dword ptr [ebp+LoadLibraryA_ptr]
	mov ebx, eax
		
	; save value
	push esi

	; resolve ImportAddressTableRVA
	mov edi, (IMAGE_DELAYLOAD_DESCRIPTOR ptr [esi]).ImportAddressTableRVA	
	add edi, dword ptr [ebp+ImageBase]

	; resolve ImportNameTableRVA
	mov esi, (IMAGE_DELAYLOAD_DESCRIPTOR ptr [esi]).ImportNameTableRVA
	add esi, dword ptr [ebp+ImageBase]
	
	; get DLL export data 
	mov edx, dword ptr [ebx+03ch]
	lea edx, dword ptr [edx+ebx+78h]
	mov edx, dword ptr [edx]
	add edx, ebx
	mov ecx, (IMAGE_EXPORT_DIRECTORY ptr [edx]).AddressOfFunctions 
	add ecx, ebx

@resolve_delayed_import:
	cmp dword ptr [esi], 0h
	je @resolve_next_delayed_DLL

	test (IMAGE_THUNK_DATA32 ptr [esi]).Ordinal, IMAGE_ORDINAL_FLAG32
	jz @resolve_delayed_import_by_names

	; resolve by ordinal
	mov eax, (IMAGE_THUNK_DATA32 ptr [esi]).Ordinal
	and eax, 0ffffh
	jmp @delayed_resolve_function_address

	; resolve functions by name
@resolve_delayed_import_by_names:

	; load function address 
	mov eax, (IMAGE_THUNK_DATA32 ptr [esi]).AddressOfData
	add eax, dword ptr [ebp+ImageBase]
	lea eax, (IMAGE_IMPORT_BY_NAME ptr [eax])._Name
	
@delayed_resolve_function_address:
	; save value
	push edx

	push eax
	push ebx	
	call dword ptr [ebp+GetProcAddress_ptr]
	
	; restore value
	pop edx

@write_delayed_function_address:
	mov (IMAGE_THUNK_DATA32 ptr [edi]).Function, eax
	cmp dword ptr [esi], 0h
	jz @f
	add esi, sizeof dword
@@:
	add edi, sizeof dword
	jmp @resolve_delayed_import

@resolve_next_delayed_DLL:
	pop esi
	add esi, sizeof IMAGE_DELAYLOAD_DESCRIPTOR 
	jmp @resolve_delayed_PE_import
@completed_resolve_delayed_PE_import:

	; *******************************
	; * step 8 - relocate addresses *
	; *******************************
	; check reloc size
	mov esi, dword ptr [ebp+PE]
	lea esi, dword ptr [esi+0a4h] ; .reloc size
	mov esi, dword ptr [esi]
	test esi, esi
	jz @pre_run
	mov edx, esi

	; read IMAGE_BASE_RELOCATION
	mov esi, dword ptr [ebp+PE]
	lea esi, dword ptr [esi+0a0h] ; .reloc rva
	mov esi, dword ptr [esi]
	add esi, dword ptr [ebp+ImageBase]
	
	; compute relocation address delta
	mov eax, dword ptr [ebp+PE]
	add eax, 34h
	mov edi, dword ptr [ebp+ImageBase]
	sub edi, dword ptr [eax]	

@relocate_block:
	; compute number of entries
	mov ecx, (IMAGE_BASE_RELOCATION ptr [esi]).SizeOfBlock		
	sub edx, ecx	

	push edx ; save back the .reloc size value

	sub ecx, sizeof IMAGE_BASE_RELOCATION
	shr ecx, 1

	; base address to relocate
	mov edx, (IMAGE_BASE_RELOCATION ptr [esi]).VirtualAddress
	add edx, dword ptr [ebp+ImageBase]

	; save value
	push esi

	; scan block entries
	add esi, sizeof IMAGE_BASE_RELOCATION

@relocate_block_entry:
	movzx eax, word ptr [esi]
	mov ebx, eax
	and ebx, 0fffh ; offset
	shr eax, 0ch ; type	
	
	cmp eax, 1h
	je @IMAGE_REL_BASED_HIGH
	cmp eax, 2h
	je @IMAGE_REL_BASED_LOW
	cmp eax, 3h
	je @IMAGE_REL_BASED_HIGHLOW
	jmp @next_block	

@IMAGE_REL_BASED_HIGH:	
	add ebx, edx
	mov eax, edi
	shr eax, 10h
	add word ptr [ebx], ax
	jmp @next_block

@IMAGE_REL_BASED_LOW:	
	add ebx, edx
	add word ptr [ebx], di
	jmp @next_block

@IMAGE_REL_BASED_HIGHLOW:
	add ebx, edx
	add dword ptr [ebx], edi
	
@next_block:
	add esi, sizeof word
	loop @relocate_block_entry

	; restore value
	pop esi

	; restore and check .reloc size
	pop edx 
	test edx, edx
	jz @pre_run

	; go to the next block
	add esi, (IMAGE_BASE_RELOCATION ptr [esi]).SizeOfBlock	
	jmp @relocate_block

	; ****************************************
	; * step 9 - Adjust PEB ImageBaseAddress *
	; ****************************************
@pre_run:
	mov esi, dword ptr [ebp+PE]
	movzx eax, word ptr [esi+016h] ; read Characteristics
	test eax, 02000h ; test for IMAGE_FILE_DLL
	jnz @PEB_adjusted_completed

	; if the module to execute is not a DLL, the PEB ImageBase
	; must be adjusted in order to correctly load the resource
	assume fs:nothing
	mov eax, fs:[30h]  ; PEB
	assume fs:error
	add eax, 8h
	mov edx, dword ptr [ebp+ImageBase]
	mov dword ptr [eax], edx
@PEB_adjusted_completed:

	; *********************************
	; * step a - Invoke TLS callbacks *
	; *********************************		
	mov esi, dword ptr [ebp+PE]
	mov eax, dword ptr [esi+0c4h] ; .tls size
	test eax, eax
	jz @invoke_TLS_completed

	; go to data directory VA
	mov esi, dword ptr [esi+0c0h] ; .tls table RVA
	add esi, dword ptr [ebp+ImageBase] ; .tls table VA

	; https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-section
	mov esi, dword ptr [esi+0ch] ; Address of Callbacks

@invoke_tls_callback:
	mov eax, dword ptr [esi]
	test eax, eax
	jz @invoke_TLS_completed
	; invoke callback
	push 0h
	push 1h; DLL_PROCESS_ATTACH
	push dword ptr [ebp+ImageBase]
	call eax

	; go to next callback
	add esi, sizeof dword
	jmp @invoke_tls_callback	
@invoke_TLS_completed:

	; ***************************************
	; * step b - insert module in Ldr field *
	; ***************************************
	mov esi, dword ptr [ebp+PE]
	movzx eax, word ptr [esi+016h] ; read Characteristics
	test eax, 02000h ; test for IMAGE_FILE_DLL
	jz @ldr_updated_completed
	
	; get the .edata directory
	xor ecx, ecx
	mov eax, dword ptr [ebp+PE]
	mov eax, dword ptr [eax+078h] 
	test eax, eax ; .edata
	jz @ldr_updated_completed

	; get the DLL name if available from the export directory .edata
	add eax, dword ptr [ebp+ImageBase]
	mov eax, dword ptr [eax+0ch]
	add eax, dword ptr [ebp+ImageBase]
	test eax, eax ; Name
	jz @f	

	; compute DLL name length
	push eax ; save value	
	push edi ; save value
	mov edi, eax
	xor eax, eax	
	dec ecx
	repne scasb
	not ecx
	inc ecx
	pop edi ; restore value
	pop eax ; restore value
@@:

	; compute allocation size for entry and DLL name	
	shl ecx, 1
	add ecx, sizeof LDR_DATA_TABLE_ENTRY32
	add ecx, sizeof LDR_DDAG_NODE32
	mov esi, eax ; save to non-volatile register

	; allocated memory for the new modules entry	
	push ecx ; save value
	push 04h; PAGE_READWRITE
	push 03000h; MEM_RESERVE|MEM_COMMIT
	push ecx
	push 0h
	call dword ptr [ebp+VirtualAlloc_ptr]
	pop ecx ; restore value
	test eax, eax
	jz @error
	mov edi, eax ; save entry data value
		
	; set DLL name
	cmp ecx, sizeof LDR_DATA_TABLE_ENTRY32 + sizeof LDR_DDAG_NODE32
	je @copy_name_completed

	; convert to unicode with a dirty tricks :)
	lea ebx, dword ptr [edi+(sizeof LDR_DATA_TABLE_ENTRY32+sizeof LDR_DDAG_NODE32)-2] ; address of unicode string
@@:
	add ebx, 2
	lodsb
	mov byte ptr [ebx], al
	test al, al
	jnz @b

	lea ebx, dword ptr [edi+sizeof LDR_DATA_TABLE_ENTRY32+sizeof LDR_DDAG_NODE32] ; address of unicode string
	sub ecx, sizeof LDR_DATA_TABLE_ENTRY32
	mov (LDR_DATA_TABLE_ENTRY32 ptr [edi]).FullDllName.Buffer, ebx
	mov (LDR_DATA_TABLE_ENTRY32 ptr [edi]).FullDllName._Length, cx
	mov (LDR_DATA_TABLE_ENTRY32 ptr [edi]).FullDllName.MaximumLength, cx
	
	mov (LDR_DATA_TABLE_ENTRY32 ptr [edi]).BaseDllName.Buffer, ebx
	mov (LDR_DATA_TABLE_ENTRY32 ptr [edi]).BaseDllName._Length, cx
	mov (LDR_DATA_TABLE_ENTRY32 ptr [edi]).BaseDllName.MaximumLength, cx
@copy_name_completed:

	; set DllBase
	mov eax, dword ptr [ebp+ImageBase]
	mov (LDR_DATA_TABLE_ENTRY32 ptr [edi]).DllBase, eax

	; set Entry Point
	mov eax, dword ptr [ebp+PE]
	mov eax, dword ptr [eax+28h]
	add eax, dword ptr [ebp+ImageBase]		
	mov (LDR_DATA_TABLE_ENTRY32 ptr [edi]).EntryPoint, eax

	; set SizeOfImage
	mov eax, dword ptr [ebp+PE]
	mov eax, dword ptr [eax+50h]
	mov (LDR_DATA_TABLE_ENTRY32 ptr [edi]).SizeOfImage, eax

	; for Flags see: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
	mov (LDR_DATA_TABLE_ENTRY32 ptr [edi]).Flags, 08a00ch ; 
	mov (LDR_DATA_TABLE_ENTRY32 ptr [edi]).LoadCount, 0ffffh

	; set DdagNode
	mov esi, edi
	add esi, sizeof LDR_DATA_TABLE_ENTRY32
	mov (LDR_DDAG_NODE32 ptr [esi]).State, 9h
	mov (LDR_DATA_TABLE_ENTRY32 ptr [edi]).DdagNode, esi	

	; modify module list to add the new entry
	assume fs:nothing
	mov esi, fs:[30h]  ; PEB
	mov esi, [esi+0ch] ; Ldr
	assume fs:error

	; push all the offsets and a terminating 0
	push 0h
	push 0h

	; InInitializationOrderModuleList
	push 10h
	push 1ch

	; InMemoryOrderModuleList
	push 8h
	push 14h

	; InLoadOrderLinks
	push 0h
	push 0ch

@add_DLL_in_ldr_modules:
	; pop offsets
	pop eax
	pop ecx
	test eax, eax
	jz @ldr_updated_completed

	; modify the last entry in the target Ldr LIST_ENTRY module list
	lea eax, dword ptr [esi+eax]
	mov eax, (LIST_ENTRY32 ptr [eax]).Blink
	lea edx, dword ptr [edi+ecx]
		
	; modify module list entry
	mov ebx, (LIST_ENTRY32 ptr [eax]).Flink
	mov (LIST_ENTRY32 ptr [eax]).Flink, edx
	mov (LIST_ENTRY32 ptr [ebx]).Blink, edx

	; modify my new entry
	mov (LIST_ENTRY32 ptr [edx]).Flink, ebx
	mov (LIST_ENTRY32 ptr [edx]).Blink, eax

	jmp @add_DLL_in_ldr_modules
@ldr_updated_completed:

	; *************************************
	; * step c - create cleanup shellcode *
	; *************************************
	; resolve VirtualQuery function
	push VirtualQuery_hash
	push dword ptr [ebp+Kernel32_base]	
	call find_func_by_hash	

	; get the size of the allocated memory
	sub esp, sizeof MEMORY_BASIC_INFORMATION32
	mov edi, esp
	push sizeof MEMORY_BASIC_INFORMATION32 ; dwLength
	push edi ; lpBuffer
	push dword ptr [ebp+MZ] ; lpAddress
	call eax
	test eax, eax
	jz @error
	mov ebx, edi ; save value to non-volatile register	

	; allocate memory for the clean-up shellcode
	push 040h; PAGE_EXECUTE_READWRITE
	push 03000h; MEM_RESERVE|MEM_COMMIT
	push 100h
	push 0h
	call dword ptr [ebp+VirtualAlloc_ptr]
	test eax, eax
	jz @error

	; write shellcode
	mov ecx, cleanup_shellcode_size
	mov edi, eax
	call @cleanup_shellcode_addr
	rep movsb

	mov esi, eax ; save shellcode addr to non-volatile reg

	; ***********************
	; * step d - invoke OEP *
	; ***********************
	; flush instruction pipeline
	push 0h
	push 0h
	push 0ffffffffh
	call dword ptr [ebp+FlushInstructionCache_ptr]

	; retrieve OEP in EDI (non-volatile)
	mov eax, dword ptr [ebp+PE]
	mov edi, dword ptr [eax+28h] ; AddressOfEntryPoint	
	add edi, dword ptr [ebp+ImageBase]		
		
	; push the DLL args. If the PE is not a DLL these values are just ignored
	assume fs:nothing
	push dword ptr fs:[20h] ; lpReserver set to the process ID
	assume fs:error
	push 1 ; fdwReason DLL_PROCESS_ATTACH
	push dword ptr [ebp+ImageBase] ; hModule

	; invoke the clean-up shellcode
	push edi
	push (MEMORY_BASIC_INFORMATION32 ptr [ebx]).RegionSize	
	push (MEMORY_BASIC_INFORMATION32 ptr [ebx]).AllocationBase		

	push esi ; save value

	; resolve VirtualFree function
	push VirtualFree_hash
	push dword ptr [ebp+Kernel32_base]	
	call find_func_by_hash	
	
	pop esi ; restore value
	
	push eax ; VirtualFree addr

	; call clean-up shellcode
	jmp esi
	
	; code after this should never be invoked

@error:
	xor eax, eax
	inc eax
	mov esp, ebp
	pop ebp
	ret
main endp

; this is necessary to be sure that there is enough 
; stape for the command-line length.
dd 0h

IFDEF DEBUG
args:
;db "C:\a\b\c\prog.exe -a -b -c 123", 0h
;dd $ - args
;db 022h, 000h, 043h, 000h, 03ah, 000h, 05ch, 000h, 057h, 000h, 06fh, 000h, 072h, 000h, 06bh
;db 000h, 073h, 000h, 070h, 000h, 061h, 000h, 063h, 000h, 065h, 000h, 05ch, 000h, 041h, 000h
;db 06ch, 000h, 061h, 000h, 06eh, 000h, 05ch, 000h, 042h, 000h, 061h, 000h, 073h, 000h, 065h
;db 000h, 06ch, 000h, 069h, 000h, 06eh, 000h, 065h, 000h, 05ch, 000h, 074h, 000h, 065h, 000h
;db 073h, 000h, 074h, 000h, 073h, 000h, 05ch, 000h, 072h, 000h, 065h, 000h, 073h, 000h, 06fh
;db 000h, 075h, 000h, 072h, 000h, 063h, 000h, 065h, 000h, 073h, 000h, 05ch, 000h, 064h, 000h
;db 075h, 000h, 06dh, 000h, 070h, 000h, 065h, 000h, 072h, 000h, 074h, 000h, 02eh, 000h, 065h
;db 000h, 078h, 000h, 065h, 000h, 022h, 000h, 020h, 000h, 022h, 000h, 02dh, 000h, 061h, 000h
;db 022h, 000h, 020h, 000h, 022h, 000h, 02dh, 000h, 062h, 000h, 022h, 000h, 020h, 000h, 022h
;db 000h, 02dh, 000h, 063h, 000h, 022h, 000h, 020h, 000h, 022h, 000h, 031h, 000h, 032h, 000h
;db 033h, 000h, 022h, 000h, 000h, 09bh, 000h, 000h, 000h
;include <test_proxy_exe.inc>
ENDIF
end main