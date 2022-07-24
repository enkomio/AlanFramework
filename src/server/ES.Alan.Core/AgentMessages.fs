namespace ES.Alan.Core

open System
open System.Collections.Generic
open ES.Alan.Core.Entities

[<AutoOpen>]
module AgentMessages =
    type NewAgentRegisteredMessage(agent: Agent) =
        member val Agent = agent with get

    type AgentCommandDataMessage(agent: Agent, commandType: AgentCommandType, data: Byte array, sourceCommand: AgentCommand) =
        member val Agent = agent with get
        member val Data = data with get
        member val CommandType = commandType with get
        member val Command = sourceCommand with get

    type AgentCommandCompletedMessage(agent: Agent, commandId: Int32, resultCode: UInt32, data: String) =
        member val Agent = agent with get
        member val CommandId = commandId with get
        member val ResultCode = resultCode with get
        member val Data = data with get
