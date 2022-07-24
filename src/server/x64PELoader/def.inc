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
	pad dword ?
	Buffer qword ?
UNICODE_STRING ends

RTL_USER_PROCESS_PARAMETERS struct
	Reserved1 byte 16 dup(?)
	Reserved2 qword 10 dup(?)
	ImagePathName UNICODE_STRING <>
	CommandLine UNICODE_STRING <>
RTL_USER_PROCESS_PARAMETERS ends

IMAGE_IMPORT_BY_NAME struct
	Hint word ?
	_Name byte ?
IMAGE_IMPORT_BY_NAME ends

IMAGE_THUNK_DATA64 union
	ForwarderString qword ?
	Function qword ?
	Ordinal qword ?
	AddressOfData qword ?
IMAGE_THUNK_DATA64 ends

IMAGE_IMPORT_DESCRIPTOR struct
	OriginalFirstThunk dword ?
	TimeDateStamp dword ?
	ForwarderChain dword ?
	_Name dword ?
	FirstThunk dword ?
IMAGE_IMPORT_DESCRIPTOR ends

IMAGE_SECTION_HEADER struct
	_Name byte 8 dup(?)
	VirtualSize dword ?
	VirtualAddress dword ?
	SizeOfRawData dword ?
	PointerToRawData dword ?
	PointerToRelocations dword ?
	PointerToLinenumbers dword ?
	NumberOfRelocations word ?
	NumberOfLinenumbers word ?
	Characteristics dword ?
IMAGE_SECTION_HEADER ends

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

MEMORY_BASIC_INFORMATION64 struct
	BaseAddress qword ?
	AllocationBase qword ?
	AllocationProtect dword ?
	__alignment1 dword ?
	RegionSize qword ?
	State dword ?
	Protect dword ?
	_Type dword ?
	__alignment2 dword ?
MEMORY_BASIC_INFORMATION64 ends

LIST_ENTRY64 struct
	Flink qword ?
	Blink qword ?
LIST_ENTRY64 ends

; definition https://github.com/processhacker/processhacker/blob/master/phnt/include/ntldr.h#L68
LDR_DDAG_NODE64 struct
	Modules LIST_ENTRY64 <>
	ServiceTagList qword ?
	LoadCount dword ?
	LoadWhileUnloadingCount dword ?
	LowestLink dword ?
	Dependencies qword ?
	IncomingDependencies qword ?
	State dword ?
	CondenseLink qword ?
	PreorderNumber dword ?
LDR_DDAG_NODE64 ends

; definition: https://github.com/processhacker/processhacker/blob/master/phnt/include/ntldr.h#L140
LDR_DATA_TABLE_ENTRY64 struct
	InLoadOrderLinks LIST_ENTRY64 <>
	InMemoryOrderModuleList LIST_ENTRY64 <>
	InInitializationOrderModuleList LIST_ENTRY64 <>
	DllBase qword ?
	EntryPoint qword ?
	SizeOfImage dword ?
	__padding1 dword ?
	FullDllName UNICODE_STRING <>
	BaseDllName UNICODE_STRING <>
	Flags dword ?
	LoadCount word ?
	TlsIndex word ?
	HashLinks LIST_ENTRY64 <>
	TimeDateStamp dword ?
	__padding2 dword ?
	EntryPointActivationContext qword ?
	_Lock qword ?
	DdagNode qword ?
	NodeModuleLink  LIST_ENTRY64 <>
	LoadContext qword ?
	ParentDllBase qword ?
	SwitchBackContext qword ?
	; ... more omitted
LDR_DATA_TABLE_ENTRY64 ends