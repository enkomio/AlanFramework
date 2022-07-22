import * as win32 from 'Win32';
import * as std from "std";

/*
 *** Resolve Win32 functions
 */
var Kernel32 = win32.LoadLibrary("Kernel32.dll");
var OpenProcessToken = win32.GetProcAddress(Kernel32, "OpenProcessToken");
var GetCurrentProcess = win32.GetProcAddress(Kernel32, "GetCurrentProcess");
var CloseHandle = win32.GetProcAddress(Kernel32, "CloseHandle");
var GetLastError = win32.GetProcAddress(Kernel32, "GetLastError");
var ReadProcessMemory = win32.GetProcAddress(Kernel32, "ReadProcessMemory");

var Advapi32 = win32.LoadLibrary("Advapi32.dll");
var OpenSCManagerA = win32.GetProcAddress(Advapi32, "OpenSCManagerA");
var OpenServiceA = win32.GetProcAddress(Advapi32, "OpenServiceA");
var QueryServiceConfigA = win32.GetProcAddress(Advapi32, "QueryServiceConfigA");
var CloseServiceHandle = win32.GetProcAddress(Advapi32, "CloseServiceHandle");
var EnumServicesStatusExA = win32.GetProcAddress(Advapi32, "EnumServicesStatusExA");
var LookupPrivilegeValueA = win32.GetProcAddress(Advapi32, "LookupPrivilegeValueA");
var AdjustTokenPrivileges = win32.GetProcAddress(Advapi32, "AdjustTokenPrivileges");

/**
 *** Helper functions ***
 */
function read_memory(address, size) {
    var buffer = new Array(size);
    var nread = new Array(8);
    while (true) {
        if (!ReadProcessMemory(GetCurrentProcess(), address, buffer, size, nread) && GetLastError() != 299 /* ERROR_PARTIAL_COPY */) {
            throw ("Error reading memory at " + address + ", code: " + GetLastError());
        }

        var error = GetLastError();
        if (error == 299 /* ERROR_PARTIAL_COPY */)
            // try again the read        
            continue;

        // buffer read, exit
        break;
    }
    return buffer;
}

function read_string(address) {
    var result = '';
    var p = address;
    while (true) {
        var i = read_memory(p, 1)[0];
        p++;

        if (i == 0)
            break;

        if (i < 32 || i > 127)
            throw ("Invalid string characters: " + i + ", address: " + p + ", error: " + GetLastError());

        var c = String.fromCharCode(i);
        result += c;
    }
    return result;
}

function t(xn) {
    var x = xn.toString(16);
    if (x.length < 2)
        return "0" + x;
    else
        return x;
}

function to_int32(x) {
    // this is HORRIBLE, but JS seems to not handle correctly shift operation
    var val = t(x[3]) + t(x[2]) + t(x[1]) + t(x[0]);
    return parseInt("0x" + val);
}

function to_int64(x) {
    // this is HORRIBLE, but JS seems to not handle correctly shift operation
    var val = t(x[7]) + t(x[6]) + t(x[5]) + t(x[4]) + t(x[3]) + t(x[2]) + t(x[1]) + t(x[0]);
    return parseInt("0x" + val);
}

function get_size(object) {
    var size = 0;
    for (const name in object) {
        var value = object[name];
        if (name.startsWith('p_')) {
            size += 8;
        }
        else if (name.startsWith('dw_')) {
            size += 4;
        }
        else if (value instanceof Array) {
            size += value.length;
        }
        else if (typeof value === "string") {
            size += 8;
        }
        else if (value instanceof Object) {
            size += get_size(value);
        }
    }

    return size;
}

function deserialize64(object, buffer) {
    var offset = 0;
    var result = {}
    for (const name in object) {
        var value = object[name];
        if (name.startsWith('p_')) {
            result[name] = to_int64(buffer.slice(offset, offset + 8));
            offset += 8;
        }
        else if (name.startsWith('dw_')) {
            result[name] = to_int32(buffer.slice(offset, offset + 4));
            offset += 4;
        }
        else if (value instanceof Array) {
            var array_value = buffer.slice(offset, offset + value.length);
            result[name] = array_value;
            offset += value.length;
        }
        else if (typeof value === "string") {
            var string_address = to_int64(buffer.slice(offset, offset + 8));
            result[name] = read_string(string_address);
            offset += 8;
        }
        else {
            var obj_size = get_size(value);
            var obj_buffer = buffer.slice(offset, offset + obj_size);
            result[name] = deserialize64(value, obj_buffer);
            offset += obj_size;
        }
    }
    return result;
}

function adjust_privileges() {
    var p_hToken = new Array(8);
    var lpLuid = new Array(8);

    if (!OpenProcessToken(GetCurrentProcess(), 0x20 | 0x8, p_hToken)) {
        throw ("Error OpenProcessToken: " + GetLastError());
    }

    if (!LookupPrivilegeValueA(0, "SeDebugPrivilege", lpLuid)) {
        throw ("Error LookupPrivilegeValueA: " + GetLastError());
    }

    // compose TOKEN_PRIVILEGES
    var sTP = new Array(0x10);

    // set sTP.Privileges[0].Luid
    sTP[4] = lpLuid[0];
    sTP[5] = lpLuid[1];
    sTP[6] = lpLuid[2];
    sTP[7] = lpLuid[3];
    sTP[8] = lpLuid[4];
    sTP[9] = lpLuid[5];
    sTP[10] = lpLuid[6];
    sTP[11] = lpLuid[7];

    // set sTP.PrivilegeCount = 1;
    sTP[0] = 0x01;
    sTP[1] = 0x00;
    sTP[2] = 0x00;
    sTP[3] = 0x00;

    // sTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    sTP[12] = 0x02;
    sTP[13] = 0x00;
    sTP[14] = 0x00;
    sTP[15] = 0x00;

    var hToken = to_int64(p_hToken);
    if (!AdjustTokenPrivileges(hToken, 0, sTP, sTP.length, 0, 0)) {
        throw ("Error AdjustTokenPrivileges: " + GetLastError());
    }

    CloseHandle(hToken);
}

/**
 *** Main Code ***
 */
adjust_privileges();

// Open service manager
var SC_HANDLE = OpenSCManagerA(
    null,           // The name of the target computer. If the pointer is NULL or points to an empty string, the function connects to the service control manager on the local computer.
    null,           // SERVICES_ACTIVE_DATABASE
    0xF003F         // Access Rights: SC_MANAGER_ALL_ACCESS (0xF003F)
);
if (!SC_HANDLE) {
    throw ("Unable to open the service manager: " + GetLastError());
}

// Obtain enumerator
var needed = new Array(8);
var returned = new Array(8);
var resume = new Array(8);

if (!EnumServicesStatusExA(
    SC_HANDLE,
    0,              // SC_ENUM_TYPE = SC_ENUM_PROCESS_INFO
    0x00000010,     // SERVICE_WIN32_OWN_PROCESS
    0x00000003,     // SERVICE_STATE_ALL
    null,           // NULL to determine required size
    0,              // 0 to determine required size
    needed,
    returned,
    resume,
    null            // Group Name can be null
) && GetLastError() != 234 /* ERROR_MORE_DATA */)
    throw ("Unable to get lpServices size: " + GetLastError());

var services_size = to_int64(needed);
var services = new Array(services_size);
if (!EnumServicesStatusExA(
    SC_HANDLE,
    0,              // SC_ENUM_TYPE = SC_ENUM_PROCESS_INFO
    0x00000010,     // SERVICE_WIN32_OWN_PROCESS
    0x00000003,     // SERVICE_STATE_ALL
    services,       // NULL to determine required size
    services_size,  // 0 to determine required size
    needed,
    returned,
    resume,
    null            // Group Name can be null
))
    throw ("Unable to get enumerate service: " + GetLastError());

// Proceeds with the enumeration
var SERVICE_STATUS_PROCESS = {
    "dw_dwServiceType": 0,
    "dw_dwCurrentState": 0,
    "dw_dwControlsAccepted": 0,
    "dw_dwWin32ExitCode": 0,
    "dw_dwServiceSpecificExitCode": 0,
    "dw_dwCheckPoint": 0,
    "dw_dwWaitHint": 0,
    "dw_dwProcessId": 0,
    "dw_dwServiceFlags": 0,
    "dw_padding": 0
};

var ENUM_SERVICE_STATUS_PROCESSA = {
    "lpServiceName": "",
    "lpDisplayName": "",
    "ServiceStatus": SERVICE_STATUS_PROCESS
}

var QUERY_SERVICE_CONFIGA = {
    "dw_dwServiceType": 0,
    "dw_dwStartType": 0,
    "dw_dwErrorControl": 0,
    "dw___padding0": 0,
    "lpBinaryPathName": "",
    "lpLoadOrderGroup": "",
    "dw_dwTagId": 0,
    "dw___padding1": 0,
    "lpDependencies": "",
    "lpServiceStartName": "",
    "lpDisplayName": ""
}

var ENUM_SERVICE_STATUS_PROCESSA_size = get_size(ENUM_SERVICE_STATUS_PROCESSA);

for (var i = 0; i < to_int64(returned); i++) {
    try {
        var offset = ENUM_SERVICE_STATUS_PROCESSA_size * i;
        var buffer = services.slice(offset, offset + ENUM_SERVICE_STATUS_PROCESSA_size);
        var service = deserialize64(ENUM_SERVICE_STATUS_PROCESSA, buffer);

        var SV_HANDLE = OpenServiceA(
            SC_HANDLE,
            service['lpServiceName'],
            0x0001 /* SERVICE_QUERY_CONFIG */
        );
        if (!SV_HANDLE)
            throw ("Unable to open the service: " + service['lpServiceName'] + ", error: " + GetLastError() + ". Try the next one.");

        var needed = new Array(8);
        if (!QueryServiceConfigA(
            SV_HANDLE,
            null,
            0,
            needed)
            && GetLastError() != 122 /* ERROR_INSUFFICIENT_BUFFER */)
            throw ("Unable to get service config size: " + GetLastError());

        var service_config_size = to_int64(needed)
        buffer = new Array(service_config_size);
        if (!QueryServiceConfigA(
            SV_HANDLE,
            buffer,
            service_config_size,
            needed)
        )
            throw ("Unable to query service: " + GetLastError());

        var service_config = deserialize64(QUERY_SERVICE_CONFIGA, buffer);
        print(
            "[+] DisplayName: " + service['lpDisplayName'] +
            " - ServiceName: " + service['lpServiceName'] +
            " - Binary path: " + service_config["lpBinaryPathName"]);
        CloseServiceHandle(SV_HANDLE);
    } catch (error) {
        print("[!!] " + error);
    }
}

CloseServiceHandle(SC_HANDLE);