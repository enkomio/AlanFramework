namespace ES.Alan.Server.Consoles

open System

type ConsoleType =
    | NoConsole
    | Dashboard
    | Agent of agentId: UInt32
    | AgentShell of agentId: UInt32

type InputTextMessage(text: String) =
    member val Text = text with get, set

type OutputTextMessage(text: String) =
    member val Text = text with get, set

type ICliConsole =    
        abstract ProcessCommand: String * String array -> ConsoleType
        abstract CommandCompleted: Int32 -> ConsoleType
        abstract GetHelp: unit -> String
        abstract PrintCursor: unit -> unit
        abstract Type: ConsoleType with get, set