namespace ES.Alan.Core

open System
open System.Collections.Generic
open ES.Alan.Core.Entities

[<AutoOpen>]
module FrameworkMessages =
    type AgentTerminatedMessage(agentId: UInt32) =
        member val AgentId = agentId with get, set

    type GetConnectedAgentsMessage() =
        member val Agents = new List<Agent>() with get, set

    type ExitAgentMessage(agentId: UInt32) =
        member val AgentId = agentId with get

    type ExecuteShellCommandMessage(agentId: UInt32, data: String) =
        member val AgentId = agentId with get
        member val Data = data with get

    type TerminateShellMessage(agentId: UInt32) =
        member val AgentId = agentId with get

    type GetSystemInfoMessage(agentId: UInt32) =
        member val AgentId = agentId with get

    type GetProcessListMessage(agentId: UInt32) =
        member val AgentId = agentId with get

    type DownloadFileMessage(agentId: UInt32, fileName: String, destDirectory: String) =
        member val AgentId = agentId with get
        member val FileName = fileName with get
        member val DestinationDirectory = destDirectory with get

    type AgentSleepMessage(agentId: UInt32, timeout: Int32, jitter: Int32) =
        member val AgentId = agentId with get
        member val Timeout = timeout with get
        member val Jitter = jitter with get

    type ProcessKillMessage(agentId: UInt32, pid: Int32) =
        member val AgentId = agentId with get
        member val Pid = pid with get

    type UploadFileMessage(agentId: UInt32, files: String array, rootPath: String, destDirectory: String) =
        member val AgentId = agentId with get
        member val Files = files with get
        member val DestinationDirectory = destDirectory with get
        member val RootPath = rootPath with get

    type NewProxyMessage(agentId: UInt32, address: String, port: String, username: String, password: String, proxyType: String) =
        member val AgentId = agentId with get
        member val Address = address with get
        member val Port = port with get
        member val Username = username with get
        member val Password = password with get
        member val Type = proxyType with get, set
        member val CreatedProxyId = String.Empty with get, set

    type UseProxyMessage(agentId: UInt32, proxy: Proxy) =
        member val AgentId = agentId with get
        member val Proxy = proxy with get

    type CloseProxyMessage(agentId: UInt32, proxy: Proxy) =
        member val AgentId = agentId with get
        member val Proxy = proxy with get

    type InfoProxyMessage(agentId: UInt32, port: Int32) =
        member val AgentId = agentId with get
        member val Port = port with get

    type StopProxyMessage(agentId: UInt32, proxy: Proxy) =
        member val AgentId = agentId with get
        member val Proxy = proxy with get

    type DeleteProxyMessage(agentId: UInt32, proxyId: UInt32) =
        member val AgentId = agentId with get
        member val ProxyId = proxyId with get

    type UpdateProxyMessage(agentId: UInt32, proxy: Proxy) =
        member val AgentId = agentId with get
        member val Proxy = proxy with get

    type CreateChainProxyMessage(agentId: UInt32, srcProxy: Proxy, destProxy: Proxy) =
        member val AgentId = agentId with get
        member val SrcProxy = srcProxy with get
        member val DestProxy = destProxy with get

    type StopChainProxyMessage(agentId: UInt32, proxy: Proxy) =
        member val AgentId = agentId with get
        member val Proxy = proxy with get

    type GetProxiesMessage() =
        member val Proxies = new List<Proxy>() with get

    type TryGetProxyMessage(address: String, port: String, username: String, password: String, proxyType: String) =
        member val Address = address with get, set
        member val Port = port with get, set
        member val Username = username with get, set
        member val Password = password with get, set
        member val Type = proxyType with get, set
        member val Proxy: Proxy option = None with get, set

    type RunMessage
        (
            agentId: UInt32, 
            pid: Int32, 
            fileName: String, 
            bitness: CpuBitness, 
            fileContent: Byte array, 
            arguments: String array, 
            packerSettings: PackerSettings, 
            interceptor: Byte array,
            runInBackground: Boolean
        ) =
        member val AgentId = agentId with get
        member val FileName = fileName with get
        member val Arguments = arguments with get        
        member val ProcessId = pid with get
        member val FileContent = fileContent with get
        member val Interceptor = interceptor with get
        member val PackerSettings = packerSettings with get
        member val Bitness = bitness with get
        member val RunInBackground = runInBackground with get

    type ExecProgramMessage(agentId: UInt32, command: String, useShell: Boolean, runInBackground: Boolean) =
        member val AgentId = agentId with get
        member val Command = command with get
        member val UseShell = useShell with get        
        member val RunInBackground = runInBackground with get

    type GetExtendedSystemInfoMessage(agentId: UInt32) =
        member val AgentId = agentId with get

    type MigrateAgentMessage
        (
            agentId: UInt32, 
            processId: Int32, 
            baseArtifact: Byte array, 
            packerSettings: PackerSettings, 
            bitness: CpuBitness
        ) =
        member val AgentId = agentId with get
        member val ProcessId = processId with get
        member val PackerSettings = packerSettings with get
        member val Bitness = bitness with get
        member val BaseArtifact = baseArtifact with get

    type NewAgentCreatedMessage(agentId: UInt32, settings: AgentSettings, packageType: Packaging, publicKey: Byte array, privateKey: Byte array) =
        member val AgentId = agentId with get
        member val Settings = settings with get, set
        member val PublicKey = publicKey with get, set
        member val PrivateKey = privateKey with get, set
        member val PackageType = packageType with get, set

    type GetEndpointsMessage() =
        member val Endpoints = new List<EndpointInfo>() with get, set

    type UpdateConfigMessage(agentId: UInt32, settings: String) =
        member val Settings = settings with get, set
        member val AgentId = agentId with get

    type GetConfigMessage(agentId: UInt32) =
        member val AgentId = agentId with get