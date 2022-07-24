namespace ES.Alan.Server.Consoles

open System
open ES.Alan.Core
open ES.Alan.Core.Entities
open ES.Fslog
open Newtonsoft.Json

type AgentShellCliConsole(messageBroker: MessageBroker, agentId: UInt32, networkUtility: NetworkUtility, logProvider: ILogProvider) =
    inherit AgentCliConsole(messageBroker, agentId, networkUtility, logProvider)
     
    override val Type = ConsoleType.AgentShell agentId with get, set

    override this.ProcessCommand(command: String, args: String array) =
        if command.Equals("exit") then
            messageBroker.Dispatch(this, new TerminateShellMessage(agentId))
            ConsoleType.Agent agentId
        elif command.Equals("detach") then            
            ConsoleType.Agent agentId
        elif command.Equals("?") || command.Equals("help") then
            base.ProcessCommand(command, args) |> ignore
            ConsoleUtility.writeText(":>")
            this.Type
        elif command.Equals("!download") && args.Length > 0 then
            base.ProcessCommand(command.TrimStart('!'), args) |> ignore
            this.Type
        elif command.Equals("!upload") && args.Length > 0 then
            base.ProcessCommand(command.TrimStart('!'), args) |> ignore
            this.Type
        else
            let commandDesc = {|
                Cmd = String.Format("{0} {1}\n", command, String.Join(' ', args))
            |}
            let data = JsonConvert.SerializeObject(commandDesc)
            messageBroker.Dispatch(this, new ExecuteShellCommandMessage(agentId, data))        
            this.Type
    
    override this.GetHelp() = 
        """
[+] Help:
        ? or help                       Show this help
        exit                            Exit from the command shell
        detach                          Detach from the command shell without terminating the shell process
        !download <remote> [<local>]    Locally download the file(s) from the agent host
        !upload <local> <remote>        Upload a local file(s) to the agent host
        <command>                       Execute the input shell command
        """

    override this.CommandCompleted(commandId: Int32) =
        ConsoleType.AgentShell agentId

    override this.PrintCursor() =
        ()