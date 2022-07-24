namespace ES.Alan.Server.Consoles

open System
open System.Text
open System.Collections.Generic
open ES.Fslog
open ES.Alan.Core
open ES.Alan.Core.Entities
open ES.Alan.Server.Consoles.ConsoleUtility
open System.Text

type CliConsole(messageBroker: MessageBroker, networkUtility: NetworkUtility, logProvider: ILogProvider) as this =
    let _consoles = new Dictionary<ConsoleType, ICliConsole>()   
    let _consoleOutput = new AgentConsoleOutput(logProvider)
    let mutable _console: ICliConsole = upcast new DashboardCliConsole(messageBroker, networkUtility, logProvider)
    let mutable _exitServer = false        

    let updateConsole(consType: ConsoleType) =
        match consType with
        | Dashboard -> 
            match _consoles.TryGetValue(consType) with
            | (true, cons) -> cons
            | _ ->
                let cons = new DashboardCliConsole(messageBroker, networkUtility, logProvider)
                _consoles.Add(consType, cons)
                upcast cons
        | Agent agent ->
            match _consoles.TryGetValue(consType) with
            | (true, cons) -> cons
            | _ ->
                let cons = new AgentCliConsole(messageBroker, agent, networkUtility, logProvider)
                _consoles.Add(consType, cons)
                upcast cons
        | AgentShell agent ->
            match _consoles.TryGetValue(consType) with
            | (true, cons) ->
                cons
            | _ ->
                let cons = new AgentShellCliConsole(messageBroker, agent, networkUtility, logProvider)
                _consoles.Add(consType, cons)
                upcast cons
        | NoConsole -> 
            _exitServer <- true
            _console

    let newAgentJoinedMessageHandler(sender: Object, message: Envelope<NewAgentRegisteredMessage>) =        
        String.Format("Agent {0} joined", message.Item.Agent.GetCleanId())        
        |> writeLineText

    let agentResultDataMessageHandler(sender: Object, message: Envelope<AgentCommandDataMessage>) =        
        _consoleOutput.ProcessCommandData(message.Item)        

    let commandCompletedMessageHandler(sender: Object, message: Envelope<AgentCommandCompletedMessage>) =        
        _consoleOutput.ProcessCommandResult(message.Item)
        
        let tmpConsole = 
            _console.CommandCompleted(message.Item.CommandId)
            |> updateConsole

        if _console.Type <> tmpConsole.Type then
            _console <- tmpConsole            

    do
        messageBroker.Subscribe(this, newAgentJoinedMessageHandler)
        messageBroker.Subscribe(this, agentResultDataMessageHandler)
        messageBroker.Subscribe(this, commandCompletedMessageHandler)

    member this.Start() =    
        _consoles.Add(ConsoleType.Dashboard, _console)
        while not _exitServer do
            _console.PrintCursor()
            let input_command = readText()
            if not <| String.IsNullOrEmpty(input_command) then
                let items = input_command.Trim().Split()
                let command = items.[0].Trim()
                let argString = 
                    items 
                    |> Array.skip 1
                    |> fun i -> String.Join(' ', i)
                let args = ConsoleUtility.parseArguments(argString)

                _console <-
                    _console.ProcessCommand(command, args)
                    |> updateConsole