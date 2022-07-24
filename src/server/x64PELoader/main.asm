comment !
x64 PE Loader, (c) Antonio 's4tan' Parata 2021
for info on the used macro, see: https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-160
x64 software convention: https://docs.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-160
Reflective Loader: https://github.com/rapid7/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c
!

Kernel32_hash equ 045a266c9h
Kernelbase_hash equ 07d33bb31h
msvcrt_hash equ 0cefaaaf3h
LoadLibraryA_hash equ 0b583c684h
GetProcAddress_hash equ 08ac5a822h
VirtualAlloc_hash equ 0e6959c02h
FlushInstructionCache_hash equ 03aa03770h
VirtualFree_hash equ 0f5fe5722h
VirtualQuery_hash equ 0cb960098h

.code

; this is necessary to jump to the correct EIP 
; when the .text section is copied
mainCRTStartup proc
	; save stack address
	mov rbx, rsp

	; align stack
	sub rsp, 10h
	and rsp, -10h

	; push stack address on the aligned stack maintaining alignment
	xor rax, rax
	push rax ; zero for padding
	push rbx ; stack address
	jmp main
mainCRTStartup endp

include <paramhelp_public.inc>

; clean-up shellcode args: 
;	- VirtualFree address
;	- base region addr
;	- region size
;	- OEP addr
;	- first arg (RCX)
;	- second arg (RDX)
;	- third arg (R8)
@cleanup_shellcode_addr:
	call @f
@@: pop rsi
	add rsi, 6
	ret

@cleanup_shellcode: 	
	; overwirte memory with 0 for security reason
	pop rbx ; VirtualFree
	pop rdi ; region addr	
	pop rcx ; region size
	pop rsi ; OEP
	pop r13 ; first arg
	pop r14 ; second arg
	pop r15  ; third arg

	xor rax, rax	
	
	push rdi ; save value

	; fill with 0
	rep stosb

	; call VirtualFree and jump to OEP
	mov r8, 08000h ; dwFreeType: MEM_RELEASE
	xor rdx, rdx
	pop rcx ; lpAddress
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call rbx ; call VirtualFree
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding

	; set the args
	mov rcx, r13
	mov rdx, r14
	mov r8, r15
	
	; call the OEP
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call rsi
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding

	; exit
	RESTORE_ALL_STD_REGS STD_FUNCTION_STACK_MIN
	add rsp, sizeof STD_FUNCTION_STACK_MIN
	
	; restore origin stack address before alignment
	pop rsp
	ret
cleanup_shellcode_size equ $ - @cleanup_shellcode

; include varisou macro utilities
include <ksamd64.inc>
include <def.inc>
include <utility.inc>

;
; this is a PIC code that searches for a PE file after its code,
; load it in memory and run the entry-point. This function start
; on a 16-byte aligned stack.
main proc frame
	alloc_stack(sizeof STD_FUNCTION_STACK_MIN)
	SAVE_ALL_STD_REGS STD_FUNCTION_STACK_MIN
.endprolog

	; ******************************
	; * step 0 - find PE in memory *
	; ******************************
	call @f
@@:	pop rsi

@search_payload:
	inc rsi
	cmp word ptr [rsi], 'ZM'
	jne @search_payload

	mov STD_FUNCTION_STACK_MIN.Parameters.MzFile[rsp], rsi ; MZ base address

	mov eax, dword ptr [rsi+03ch]
	; safety check to avoid potential access violation
	cmp eax, 500h
	ja @search_payload

	; check PE signature
	lea rax, qword ptr [rsi+rax]
	cmp word ptr [rax], 'EP'
	jne @search_payload
	mov STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp], rax ; PE base address

	; ***************************************
	; * step 1 - find Kernel32 base address *
	; ***************************************
	mov rcx, Kernel32_hash
	call find_lib_by_hash	
	test rax, rax
	jz @error
	mov STD_FUNCTION_STACK_MIN.Parameters.Kernel32Base[rsp], rax ; kernel32 base	

	; ******************************************
	; * step 2 - change command-line arguments *
	; ******************************************
	; get the the command-line size
	mov rsi, STD_FUNCTION_STACK_MIN.Parameters.MzFile[rsp]
	lea rsi, qword ptr [rsi-sizeof qword]
	cmp qword ptr [rsi], 0h
	je @command_line_change_end

	; allocated memory for command-line
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.Kernel32Base[rsp]
	mov rdx, VirtualAlloc_hash
	call find_func_by_hash

	mov r9, 040h; PAGE_EXECUTE_READWRITE
	mov r8, 03000h; MEM_RESERVE | MEM_COMMIT
	mov rdx, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp]
	mov rdx, qword ptr [rsi]		
	xor rcx, rcx
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call rax
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding
	test rax, rax
	jz @error

	; copy the command-line to the newly allocated memory
	mov rcx, qword ptr [rsi]
	mov rdi, rax
	mov r15, qword ptr [rsi] ; save value
	sub rsi, qword ptr [rsi]
	rep movsb
	
	; http://bytepointer.com/resources/tebpeb64.htm
	; change PEB->ProcessParameters CommandLine and ImagePathName
	mov rbx, gs:[60h] ; PEB
	mov rbx, qword ptr [rbx+20h]
	lea rbx, (RTL_USER_PROCESS_PARAMETERS ptr [rbx]).CommandLine

	mov rcx, r15
	mov (UNICODE_STRING ptr [rbx])._Length, cx
	add cx, sizeof word
	mov (UNICODE_STRING ptr [rbx]).MaximumLength, cx
	mov (UNICODE_STRING ptr [rbx]).Buffer, rax

	; invoke again Kernelbase entry-point to invalidate cache
	mov rcx, Kernelbase_hash
	call find_lib_by_hash	
	test rax, rax
	jz @error
	lea rsi, qword ptr [rax+03ch]
	mov esi, dword ptr [rsi]
	add rsi, rax ; PE

	mov esi, dword ptr [rsi+28h] ; Kernelbase AddressOfEntryPoint	
	add rsi, rax
		
	xor r8, r8 ; lpReserved 
	mov rdx, 1h ; fdwReason
	mov rcx, rax ; hinstDLL
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call rsi
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding

	; invoke again msvcrt entry-point to invalidate cache
	mov rcx, msvcrt_hash
	call find_lib_by_hash	
	test rax, rax
	jz @load_msvcrt
	lea rsi, qword ptr [rax+03ch]
	mov esi, dword ptr [rsi]
	add rsi, rax ; PE

	mov esi, dword ptr [rsi+28h] ; msvcrt AddressOfEntryPoint	
	add rsi, rax
		
	xor r8, r8 ; lpReserved 
	mov rdx, 1h ; fdwReason
	mov rcx, rax ; hinstDLL
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call rsi
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding
	jmp @command_line_change_end

@load_msvcrt:
	; resolve LoadLibraryA
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.Kernel32Base[rsp]
	mov rdx, LoadLibraryA_hash
	call find_func_by_hash

	; msvcrt is not loaded, load it before time
	mov r10, 0000074726376736dh
	push r10
	mov rcx, rsp
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call rax
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding
	pop r10

@command_line_change_end:

	; **********************************
	; * step 3 - allocate space for PE *
	; **********************************
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.Kernel32Base[rsp]
	mov rdx, VirtualAlloc_hash
	call find_func_by_hash

	mov r9, 040h; PAGE_EXECUTE_READWRITE
	mov r8, 03000h; MEM_RESERVE | MEM_COMMIT
	mov rdx, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp]
	mov edx, dword ptr [rdx+050h]		
	xor rcx, rcx
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call rax
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding
	test rax, rax
	jz @error
	mov STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp], rax ; Injected MZ base

	; ***************************
	; * step 4 - copy PE header *
	; ***************************
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp]
	add rcx, 054h
	mov ecx, dword ptr [rcx] ; SizeOfHEaders
	mov rsi, STD_FUNCTION_STACK_MIN.Parameters.MzFile[rsp]
	mov rdi, rax
	rep movsb

	; **************************
	; * step 5 - copy sections *
	; **************************
	mov rax, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp]
	movzx r10, word ptr [rax+6h] ; NumberOfSections
	movzx r13, word ptr [rax+14h] ; SizeOfOptionalHeaders
	add r13, 018h ; add the size of FileHeader
	add r13, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp] ; pointer to the first section

@map_section:	
	mov edi, IMAGE_SECTION_HEADER.VirtualAddress[r13]
	add rdi, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp] ; section VA
	mov ecx, IMAGE_SECTION_HEADER.SizeOfRawData[r13]
	mov esi, IMAGE_SECTION_HEADER.PointerToRawData[r13]
	add rsi, STD_FUNCTION_STACK_MIN.Parameters.MzFile[rsp] ; PointerToRawData VA
	rep movsb	

	; go to next section
	add r13, sizeof IMAGE_SECTION_HEADER
	dec r10
	jnz @map_Section

	; *******************************
	; * step 6 - resolve PE imports *
	; *******************************
	; https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-idata-section
	mov rax, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp]
	cmp dword ptr [rax+094h], 0h ; check Import Directory Size
	je @resolve_import_completed

	; get import data directory
	mov esi, dword ptr [rax+090h] ; .idata rva
	add rsi, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp] ; .idata VA	

	; resolve GetProcAddress
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.Kernel32Base[rsp]
	mov rdx, GetProcAddress_hash
	call find_func_by_hash
	mov r14, rax

	; resolve LoadLibraryA
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.Kernel32Base[rsp]
	mov rdx, LoadLibraryA_hash
	call find_func_by_hash
	mov r15, rax ; save LoadLibrary function address

@resolve_PE_imports:
	mov ecx, (IMAGE_IMPORT_DESCRIPTOR ptr [rsi])._Name
	test rcx, rcx
	jz @resolve_next_DLL

	; get thunk data containing information on the imported functions
	mov r12d, (IMAGE_IMPORT_DESCRIPTOR ptr [rsi]).FirstThunk	
	add r12, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp] ; FirstThunk VAResolvedDllHandle
	mov r13d, (IMAGE_IMPORT_DESCRIPTOR ptr [rsi]).OriginalFirstThunk
	add r13, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp] ; OriginalFirstThunk VA

	; load the specified library
	mov ecx, (IMAGE_IMPORT_DESCRIPTOR ptr [rsi])._Name
	add rcx, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp]
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call r15
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding
	test rax, rax
	jz @error
	mov STD_FUNCTION_STACK_MIN.Parameters.ResolvedDllHandle[rsp], rax ; DLL handle

	; get loaded DLL export data to resolve functions
	mov edx, dword ptr [rax+03ch]
	lea rdx, dword ptr [rdx+rax+088h]
	mov edx, dword ptr [rdx] ; DLL .edata RVA
	test edx, edx
	jz @error
	add rdx, rax ; DLL .edata VA
	mov STD_FUNCTION_STACK_MIN.Parameters.ResolvedEdata[rsp], rdx ; DLL .edata VA

@resolve_DLL_imports:
	cmp dword ptr [r13], 0h
	je @resolve_next_DLL

	; get DLL .edata VA
	mov rdx, STD_FUNCTION_STACK_MIN.Parameters.ResolvedEdata[rsp]

	; check type
	mov rax, 1
	shl rax, 63 ; IMAGE_ORDINAL_FLAG64
	test (IMAGE_THUNK_DATA64 ptr [r13]).Ordinal, rax
	jz @resolve_import_by_names

	; get the address of exported functions
	mov ebx, (IMAGE_EXPORT_DIRECTORY ptr [rdx]).AddressOfFunctions 
	add rbx, rax ; AddressOfFunctions VA

	; resolve function by ordinal
	mov rdx, (IMAGE_THUNK_DATA64 ptr [r13]).Ordinal
	and rdx, 0ffffh ; function ordinal	
	jmp @resolve_function_address

@resolve_import_by_names:
	; obtain the imported function name
	mov rdx, (IMAGE_THUNK_DATA64 ptr [r13]).AddressOfData
	add rdx, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp] ; 
	lea rdx, (IMAGE_IMPORT_BY_NAME ptr [rdx])._Name
	
@resolve_function_address:
	; resolve the function address
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.ResolvedDllHandle[rsp]	
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call r14
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding	
	
@write_function_address:
	mov (IMAGE_THUNK_DATA64 ptr [r12]).Function, rax
	cmp qword ptr [r13], 0h
	jz @f
	add r13, sizeof qword ; go to next OriginalFirstThunk
@@:
	add r12, sizeof qword ; go to next FirstThunk
	jmp @resolve_DLL_imports

@resolve_next_DLL:
	add rsi, sizeof IMAGE_IMPORT_DESCRIPTOR 
	cmp dword ptr [rsi], 0h
	jz @resolve_import_completed
	jmp @resolve_PE_imports
@resolve_import_completed:

	; ***************************************
	; * step 7 - resolve delayed PE imports *
	; ***************************************
	; https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#delay-load-import-tables-image-only
	mov rax, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp]
	cmp dword ptr [rax+0f4h], 0h ; .Delay-Load Import Tables size
	je @resolve_delayed_import_completed ; check size

	; get import data directory
	mov esi, dword ptr [rax+0f0h] ; .Delay-Load Import Tables rva
	add rsi, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp] ; .Delay-Load Import Tables VA	

@resolve_PE_delayed_imports:
	; load library
	mov ecx, (IMAGE_DELAYLOAD_DESCRIPTOR ptr [rsi]).DllNameRVA
	add rcx, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp] ; DLL name VA
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call r15 ; LoadLibrary(DllName)
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding
	test rax, rax
	jz @error
	mov STD_FUNCTION_STACK_MIN.Parameters.ResolvedDllHandle[rsp], rax ; DLL handle

	; get name and address offset
	mov r12d, (IMAGE_DELAYLOAD_DESCRIPTOR ptr [rsi]).ImportAddressTableRVA
	add r12, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp] ; ImportAddressTable VA	
	mov r13d, (IMAGE_DELAYLOAD_DESCRIPTOR ptr [rsi]).ImportNameTableRVA
	add r13, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp] ; ImportNameTable VA	
	
@resolve_DLL_imports_delayed:
	cmp dword ptr [r13], 0h
	je @resolve_next_delayed_DLL

	; get DLL .edata VA
	mov rdx, STD_FUNCTION_STACK_MIN.Parameters.ResolvedEdata[rsp]

	; check type
	mov rax, 1
	shl rax, 63 ; IMAGE_ORDINAL_FLAG64
	test (IMAGE_THUNK_DATA64 ptr [r13]).Ordinal, rax
	jz @resolve_delayed_import_by_names

	; get the address of exported functions
	mov ebx, (IMAGE_EXPORT_DIRECTORY ptr [rdx]).AddressOfFunctions 
	add rbx, rax ; AddressOfFunctions VA

	; resolve function by ordinal: (Ordinal - Base) * sizeof(DWORD)	
	mov rax, (IMAGE_THUNK_DATA64 ptr [r13]).Ordinal
	and rax, 0ffffh ; function ordinal
	sub eax, (IMAGE_EXPORT_DIRECTORY ptr [rdx]).Base	
	lea rax, [rax * sizeof dword]
		
	; dereference value
	add rax, rdx ; Add AddressOfFunctions VA
	mov eax, dword ptr [rax]
	add rax, STD_FUNCTION_STACK_MIN.Parameters.ResolvedDllHandle[rsp]
	jmp @write_function_address_delayed

@resolve_delayed_import_by_names:
	; obtain the imported function name
	mov rdx, (IMAGE_THUNK_DATA64 ptr [r13]).AddressOfData
	add rdx, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp] ; 
	lea rdx, (IMAGE_IMPORT_BY_NAME ptr [rdx])._Name
	
	; resolve the function address
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.ResolvedDllHandle[rsp]	
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call r14
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding
		
@write_function_address_delayed:
	mov (IMAGE_THUNK_DATA64 ptr [r12]).Function, rax
	cmp qword ptr [r13], 0h
	jz @f
	add r13, sizeof qword ; go to next OriginalFirstThunk
@@:
	add r12, sizeof qword ; go to next FirstThunk
	jmp @resolve_DLL_imports_delayed

@resolve_next_delayed_DLL:
	add rsi, sizeof IMAGE_DELAYLOAD_DESCRIPTOR 
	cmp dword ptr [rsi], 0h
	jz @resolve_delayed_import_completed
	jmp @resolve_PE_delayed_imports
@resolve_delayed_import_completed:

	; *******************************
	; * step 8 - relocate addresses *
	; *******************************
	mov rax, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp]
	mov r11d, dword ptr [rax+0b4h]
	test r11, r11 ; .reloc size
	je @relocation_completed ; check size

	; compute relocation address delta
	mov rax, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp]
	mov rcx, qword ptr [rax+30h] ; read PE base address
	mov r13, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp]
	sub r13, rcx ; compute delta to add to address to relocate

	; read relocation data directory
	mov r12d, dword ptr [rax+0b0h] ; .reloc rva
	add r12, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp] ; .reloc VA. Pointer to relocation block

@relocate_block:
	test r11, r11
	jz @relocation_completed

	; compute number of entries in the current block
	mov ecx, (IMAGE_BASE_RELOCATION ptr [r12]).SizeOfBlock
	sub r11, rcx	
	sub rcx, sizeof IMAGE_BASE_RELOCATION
	shr rcx, 1 ; div sizeof (IMAGE_RELOC) to obtain the number of entries

	; address to relocate
	mov edx, (IMAGE_BASE_RELOCATION ptr [r12]).VirtualAddress
	add rdx, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp]

	; skip header to obtain the block content
	add r12, sizeof IMAGE_BASE_RELOCATION

@relocate_block_entry:
	; obtain block entry offset and type
	movzx rax, word ptr [r12]
	mov rbx, rax
	and rbx, 0fffh ; offset
	shr rax, 0ch ; type	
	
	; inspect type for the kind of relocation
	cmp rax, 1h
	je @IMAGE_REL_BASED_HIGH
	cmp rax, 2h
	je @IMAGE_REL_BASED_LOW
	cmp rax, 3h
	je @IMAGE_REL_BASED_HIGHLOW
	cmp eax, 0ah
	je @IMAGE_REL_BASED_DIR64
	jmp @next_block_entry	

@IMAGE_REL_BASED_DIR64:
	add rbx, rdx ; add offset to obtain the effective relocated address
	add qword ptr [rbx], r13 ; relocate address
	jmp @next_block_entry

@IMAGE_REL_BASED_HIGH:	
	add rbx, rdx ; add offset to obtain the effective relocated address
	mov rax, r13 ; shift delta to get high WORD value (upper 16 bit)
	shr rax, 10h
	add word ptr [rbx], ax ; relocate address
	jmp @next_block_entry

@IMAGE_REL_BASED_LOW:	
	add rbx, rdx ; add offset to obtain the effective relocated address
	add word ptr [ebx], r13w ; relocate address
	jmp @next_block_entry

@IMAGE_REL_BASED_HIGHLOW:
	add rbx, rdx ; add offset to obtain the effective relocated address
	add dword ptr [rbx], r13d ; relocate address
	
@next_block_entry:
	add r12, sizeof word
	loop @relocate_block_entry
	jmp @relocate_block
@relocation_completed:

	; ****************************************
	; * step 9 - Adjust PEB ImageBaseAddress *
	; ****************************************
	mov rax, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp] ; PE VA
	movzx rax, word ptr [rax+016h] ; read Characteristics
	test rax, 02000h ; test for IMAGE_FILE_DLL
	jnz @PEB_adjusted_completed

	; if the module to execute is not a DLL, the PEB ImageBase
	; must be adjusted in order to correctly load the resource
	mov rax, gs:[60h]
	add rax, 010h
	mov rdx, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp]
	mov qword ptr [rax], rdx
@PEB_adjusted_completed:

	; *********************************
	; * step a - Invoke TLS callbacks *
	; *********************************		
	mov rax, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp] ; PE VA
	mov ecx, dword ptr [rax+0d4h] ; .tls size
	test rcx, rcx
	jz @invoke_TLS_completed

	; go to data directory VA
	mov esi, dword ptr [rax+0d0h] ; .tls rva
	add rsi, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp] ; .tls VA

	; https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-section
	mov rsi, qword ptr [rsi+18h] ; Address of Callbacks

@invoke_tls_callback:
	mov rax, qword ptr [rsi]
	test rax, rax
	jz @invoke_TLS_completed
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp]
	mov rdx, 1h; DLL_PROCESS_ATTACH
	xor r8, r8
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call rax
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding
	add rsi, sizeof qword
	jmp @invoke_tls_callback
@invoke_TLS_completed:

	; ***************************************
	; * step b - insert module in Ldr field *
	; ***************************************
	; check if it is a DLL, if not skip this step
	mov rax, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp]
	movzx ecx, word ptr [rax+16h] ; Characteristics	
	test rcx, 2000h ; IMAGE_FILE_DLL
	jz @ldr_updated_completed

	; get .edata VirtualAddress
	mov rax, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp]
	mov eax, dword ptr [rax+088h] 
	test rax, rax
	jz @ldr_updated_completed
	add rax, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp] 

	; default name length
	xor rcx, rcx
	
	; get the DLL name if available from the export directory
	mov edi, dword ptr [rax+0ch] ; name RVA
	add rdi, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp]
	test rdi, rdi ; Name
	jz @f	

	; save pointer
	mov rsi, rdi

	; compute DLL name length	
	xor rax, rax		
	dec rcx
	repne scasb
	not rcx
@@:
	; compute allocation size for entry and DLL name	
	shl rcx, 1
	add rcx, sizeof LDR_DATA_TABLE_ENTRY64
	add rcx, sizeof LDR_DDAG_NODE64
	mov r15, rcx ; save value

	; allocated memory for the new modules entry	
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.Kernel32Base[rsp]
	mov rdx, VirtualAlloc_hash
	call find_func_by_hash

	mov r9, 04h; PAGE_READWRITE
	mov r8, 03000h; MEM_RESERVE | MEM_COMMIT
	mov rdx, r15
	xor rcx, rcx
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call rax
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding
	test rax, rax
	jz @error
	mov r12, rax ; save value

	; set DLL name
	cmp r15, sizeof LDR_DATA_TABLE_ENTRY64 + sizeof LDR_DDAG_NODE64
	je @copy_name_completed

	; convert to unicode with a dirty tricks :)
	lea rbx, dword ptr [r12+(sizeof LDR_DATA_TABLE_ENTRY64+sizeof LDR_DDAG_NODE64)-2] ; address of unicode string - 2
	
@@:
	add rbx, 2
	lodsb
	mov byte ptr [rbx], al
	test al, al
	jnz @b

	; copy the string to the FullDllName and BaseDllName
	lea rbx, dword ptr [r12+sizeof LDR_DATA_TABLE_ENTRY64+sizeof LDR_DDAG_NODE64] ; address of unicode string
	mov rcx, r15
	sub rcx, sizeof LDR_DATA_TABLE_ENTRY64+sizeof LDR_DDAG_NODE64
	mov (LDR_DATA_TABLE_ENTRY64 ptr [r12]).FullDllName.Buffer, rbx
	mov (LDR_DATA_TABLE_ENTRY64 ptr [r12]).FullDllName._Length, cx
	mov (LDR_DATA_TABLE_ENTRY64 ptr [r12]).FullDllName.MaximumLength, cx	
	mov (LDR_DATA_TABLE_ENTRY64 ptr [r12]).BaseDllName.Buffer, rbx
	mov (LDR_DATA_TABLE_ENTRY64 ptr [r12]).BaseDllName._Length, cx
	mov (LDR_DATA_TABLE_ENTRY64 ptr [r12]).BaseDllName.MaximumLength, cx
@copy_name_completed:

	; set DllBase
	mov rax, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp]
	mov (LDR_DATA_TABLE_ENTRY64 ptr [r12]).DllBase, rax

	; set Entry Point
	mov rbx, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp]
	mov eax, dword ptr [rbx+28h] ; AddressOfEntryPoint RVA
	add rax, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp]
	mov (LDR_DATA_TABLE_ENTRY64 ptr [r12]).EntryPoint, rax

	; set SizeOfImage
	mov eax, dword ptr [rbx+50h]
	mov (LDR_DATA_TABLE_ENTRY64 ptr [r12]).SizeOfImage, eax

	; for Flags see: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
	mov (LDR_DATA_TABLE_ENTRY64 ptr [r12]).Flags, 08a00ch ; 
	mov (LDR_DATA_TABLE_ENTRY64 ptr [r12]).LoadCount, 0ffffh

	; set DdagNode
	mov rax, r12
	add rax, sizeof LDR_DATA_TABLE_ENTRY64
	mov (LDR_DDAG_NODE64 ptr [rax]).State, 9h
	mov (LDR_DATA_TABLE_ENTRY64 ptr [r12]).DdagNode, rax

	; modify module list to add the new entry
	mov rax, gs:[60h] ; PEB
	mov rsi, [rax+018h] ; Ldr

	; push all the offsets and a terminating 0
	push 0h
	push 0h

	; InInitializationOrderModuleList
	push 020h
	push 030h

	; InMemoryOrderModuleList
	push 010h
	push 020h

	; InLoadOrderLinks
	push 0h
	push 010h

	@add_DLL_in_ldr_modules:
	; pop offsets
	pop rax
	pop rcx
	test rax, rax
	jz @ldr_updated_completed

	; modify the last entry in the target Ldr LIST_ENTRY module list
	lea rax, qword ptr [rsi+rax]
	mov rax, (LIST_ENTRY64 ptr [rax]).Blink
	lea rdx, qword ptr [r12+rcx]
		
	; modify module list entry
	mov rbx, (LIST_ENTRY64 ptr [rax]).Flink
	mov (LIST_ENTRY64 ptr [rax]).Flink, rdx
	mov (LIST_ENTRY64 ptr [rbx]).Blink, rdx

	; modify my new entry
	mov (LIST_ENTRY64 ptr [rdx]).Flink, rbx
	mov (LIST_ENTRY64 ptr [rdx]).Blink, rax
	jmp @add_DLL_in_ldr_modules
@ldr_updated_completed:

	; *************************************
	; * step c - create cleanup shellcode *
	; *************************************
	; resolve VirtualQuery function
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.Kernel32Base[rsp]
	mov rdx, VirtualQuery_hash
	call find_func_by_hash	
	
	mov r8, sizeof MEMORY_BASIC_INFORMATION64 ; dwLength
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.MzFile[rsp] ; lpAddress

	; get the size of the allocated memory
	sub rsp, sizeof MEMORY_BASIC_INFORMATION64
	mov rbx, rsp ; save value
	mov rdx, rbx ; lpBuffer
	
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call rax
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding	
	
	; read the region properties before to repristinate the stack
	mov r14, (MEMORY_BASIC_INFORMATION64 ptr [rbx]).RegionSize	
	mov r15, (MEMORY_BASIC_INFORMATION64 ptr [rbx]).AllocationBase
	add rsp, sizeof MEMORY_BASIC_INFORMATION64
	
	test rax, rax
	jz @error

	; allocate memory for the clean-up shellcode
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.Kernel32Base[rsp]
	mov rdx, VirtualAlloc_hash
	call find_func_by_hash

	mov r9, 040h; PAGE_EXECUTE_READWRITE
	mov r8, 03000h; MEM_RESERVE | MEM_COMMIT
	mov rdx, 100h
	xor rcx, rcx
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call rax
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding
	test rax, rax
	jz @error

	mov rbx, rax ; save value

	; write shellcode
	mov rcx, cleanup_shellcode_size
	mov rdi, rax
	call @cleanup_shellcode_addr 
	rep movsb
		
	; ***********************
	; * step d - invoke OEP *
	; ***********************
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.Kernel32Base[rsp]
	mov rdx, FlushInstructionCache_hash
	call find_func_by_hash

	; flush instruction cache
	xor rdx, rdx
	xor r8, r8
	mov rcx, 0ffffffffffffffffh
	sub rsp, (sizeof qword * 5) ; home stack space4 regs + padding
	call rax
	add rsp, (sizeof qword * 5) ; clear home stack space4 regs + padding
	test rax, rax
	jz @error	

	; get the PE type
	mov rax, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp]
	movzx ecx, word ptr [rax+16h] ; Characteristics

	; clear the registries that hold the arguments
	xor r8, r8
	xor r9, r9
	xor r10, r10

	; check if it is a DLL
	test rcx, 2000h ; IMAGE_FILE_DLL
	jz @call_OEP

	; set the hinstDLL and fdwReason (GetCurrentProcessId) as argument
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp]
	mov rdx, 1h ; fdwReason DLL_PROCESS_ATTACH
	mov r8, qword ptr gs:[40h] ; lpReserver set to the process ID

	; save values
	mov r9, rdx
	mov r10, rcx
		
@call_OEP:
	; compute OEP
	mov r12, STD_FUNCTION_STACK_MIN.Parameters.PeFile[rsp]
	mov r12d, dword ptr [r12+28h] ; AddressOfEntryPoint RVA
	add r12, STD_FUNCTION_STACK_MIN.Parameters.ImageBase[rsp] ; AddressOfEntryPoint VA

	; resolve VirtualFree function
	mov rcx, STD_FUNCTION_STACK_MIN.Parameters.Kernel32Base[rsp]
	mov rdx, VirtualFree_hash
	call find_func_by_hash	
	
	; invoke the clean-up shellcode
	push r8 ; third arg
	push r9 ; second arg
	push r10 ; first arg
	push r12 ; OEP addr
	push r14 ; region size
	push r15 ; base region addr
	push rax ; VirtualFree address
	jmp rbx

	; code after this should never be invoked under normal circumstance	

@error:	
	xor rax, rax
	inc rax

	RESTORE_ALL_STD_REGS STD_FUNCTION_STACK_MIN
	add rsp, sizeof STD_FUNCTION_STACK_MIN
	
	; restore origin stack address before alignment
	pop rsp
	ret
main endp

; this is necessary to be sure that there is enough 
; space for the command-line length.
dq 0h

; de-comment line below for debuging
;args:
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
;db 033h, 000h, 022h, 000h, 000h, 09bh, 000h, 000h, 000h, 000h, 000h, 000h, 000h
;include <test_proxy_exe.inc>

end