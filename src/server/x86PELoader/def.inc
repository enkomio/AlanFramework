; local vars
local0 equ -4h
local1 equ -8h
local2 equ -0Ch
local3 equ -10h
local4 equ -14h
local5 equ -18h
local6 equ -1Ch
local7 equ -20h
local8 equ -24h
local9 equ -28h
local10 equ -2ch
local11 equ -30h

; arguments
arg0 equ 8h
arg1 equ 0Ch
arg2 equ 10h
arg3 equ 14h

IMAGE_ORDINAL_FLAG32 equ 080000000h
IMAGE_FILE_DLL equ 02000h
PAGE_EXECUTE_WRITECOPY equ 80h

IMAGE_BASE_RELOCATION struct
	VirtualAddress dword ?
	SizeOfBlock dword ?
IMAGE_BASE_RELOCATION ends

IMAGE_EXPORT_DIRECTORY struct
    Characteristics dword ?
    TimeDateStamp dword ?
    MajorVersion word ?
    MinorVersion word ?
    _Name dword ? 
    Base dword ?
    NumberOfFunctions dword ?
    NumberOfNames dword ?
    AddressOfFunctions dword ?
    AddressOfNames dword ?
    AddressOfNameOrdinals dword ?
IMAGE_EXPORT_DIRECTORY ends

UNICODE_STRING struct
	_Length word ?
	MaximumLength word ?
	Buffer dword ?
UNICODE_STRING ends

RTL_USER_PROCESS_PARAMETERS struct
	Reserved1 byte 16 dup(?)
	Reserved2 dword 10 dup(?)
	ImagePathName UNICODE_STRING <>
	CommandLine UNICODE_STRING <>
RTL_USER_PROCESS_PARAMETERS ends

IMAGE_IMPORT_BY_NAME struct
	Hint word ?
	_Name byte ?
IMAGE_IMPORT_BY_NAME ends

IMAGE_THUNK_DATA32 union
	ForwarderString dword ?
	Function dword ?
	Ordinal dword ?
	AddressOfData dword ?
IMAGE_THUNK_DATA32 ends

IMAGE_IMPORT_DESCRIPTOR struct
	OriginalFirstThunk dword ?
	TimeDateStamp dword ?
	ForwarderChain dword ?
	_Name dword ?
	FirstThunk dword ?
IMAGE_IMPORT_DESCRIPTOR ends

IMAGE_DELAYLOAD_DESCRIPTOR struct
	Attributes dword ?
	DllNameRVA dword ?
	ModuleHandleRVA dword ?
	ImportAddressTableRVA dword ?
	ImportNameTableRVA dword ?
	BoundImportAddressTableRVA dword ?
	UnloadInformationTableRVA dword ?
	TimeDateStamp dword ?
IMAGE_DELAYLOAD_DESCRIPTOR ends

MEMORY_BASIC_INFORMATION32 struct
	BaseAddress dword ?
	AllocationBase dword ?
	AllocationProtect dword ?
	RegionSize dword ?
	State dword ?
	Protect dword ?
	_Type dword ?
MEMORY_BASIC_INFORMATION32 ends

LIST_ENTRY32 struct
	Flink dword ?
	Blink dword ?
LIST_ENTRY32 ends

LDR_DDAG_NODE32 struct
	Modules LIST_ENTRY32 <>
	ServiceTagList dword ?
	LoadCount dword ?
	LoadWhileUnloadingCount dword ?
	LowestLink dword ?
	Dependencies dword ?
	IncomingDependencies dword ?
	State dword ?
	CondenseLink dword ?
	PreorderNumber dword ?
LDR_DDAG_NODE32 ends

; full definition: https://github.com/processhacker/processhacker/blob/master/phnt/include/ntldr.h#L140
LDR_DATA_TABLE_ENTRY32 struct
	InLoadOrderLinks LIST_ENTRY32 <>
	InMemoryOrderModuleList LIST_ENTRY32 <>
	InInitializationOrderModuleList LIST_ENTRY32 <>
	DllBase dword ?
	EntryPoint dword ?
	SizeOfImage dword ?
	FullDllName UNICODE_STRING <>
	BaseDllName UNICODE_STRING <>
	Flags dword ?
	LoadCount word ?
	TlsIndex word ?
	HashLinks LIST_ENTRY32 <>
	TimeDateStamp dword ?
	EntryPointActivationContext dword ?
	_Lock dword ?
	DdagNode dword ?
	NodeModuleLink  LIST_ENTRY32 <>
	LoadContext dword ?
	ParentDllBase dword ?
	SwitchBackContext dword ?
	; ... more omitted
LDR_DATA_TABLE_ENTRY32 ends