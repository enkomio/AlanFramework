import * as win32 from 'Win32';

var kernel32 = win32.LoadLibrary("kernel32.dll");
var GetCurrentProcessId = win32.GetProcAddress(kernel32, "GetCurrentProcessId");
var IsWow64Process = win32.GetProcAddress(kernel32, "IsWow64Process");
var GetCurrentProcess = win32.GetProcAddress(kernel32, "GetCurrentProcess");


var my_pid = GetCurrentProcessId();
var is_wow64 = new Array(4);
IsWow64Process(GetCurrentProcess(), is_wow64);

var msg = "Hello world from Javascript executed in process: " + my_pid;
if (is_wow64[0] == 1)
	msg += " - I'm running under Wow64 :)";
print(msg);
