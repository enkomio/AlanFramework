namespace ES.Alan.Core

open System
open System.IO
open System.Reflection
open System.Collections.Generic
open ES.Alan.Core.Entities
open ES.Fslog

type AgentSessionDto() =
    member val Id = String.Empty with get, set
    member val AgentId = 0u with get, set
    member val PrivateKey = String.Empty with get, set
    member val Settings = String.Empty with get, set

type AgentService(messageBroker: MessageBroker, logProvider: ILogProvider) as this =
    let _syncRoot = new Object()
    let _sessions = new Dictionary<UInt32, AgentSession>()

    let _logger =
        log "AgentService"
        |> verbose "AgentNotFound" "Agent id {0} not found"        
        |> buildAndAdd(logProvider)
   
    let decodeAgentSessionId(agentSessionId: String) =
        let rawAgentSessionId = new MemoryStream(Convert.FromBase64String(agentSessionId))
        use binReader = new BinaryReader(rawAgentSessionId)
        let sessionId = binReader.ReadUInt32()
        let agentPublicKey = binReader.ReadBytes(32)
        (sessionId, agentPublicKey)

    let tryLoadSessionFromDb(agentId: UInt32) =
        use agentRepository = new ObjectRepository<AgentSessionDto>()
        agentRepository.Get(agentId.ToString("X"))

    let rec handle(agentSessionId: String, entryPoint: String, agentAddress: String, agentPort: Int32, inputRequest: Byte array, listener: IListener) =
        let (sessionId, publicKey) = decodeAgentSessionId(agentSessionId)
        match _sessions.TryGetValue(sessionId) with
        | (true, agentSession) ->
            agentSession.Handle(
                publicKey, 
                agentSessionId,
                entryPoint,
                agentAddress,
                agentPort,
                inputRequest,
                listener
            )
        | _ ->
            match tryLoadSessionFromDb(sessionId) with
            | Some savedSession ->             
                let agentSession = 
                    new AgentSession(
                        Convert.FromBase64String(savedSession.PrivateKey), 
                        AgentSettings.Read(savedSession.Settings), 
                        messageBroker, 
                        logProvider
                    )
                _sessions.[sessionId] <- agentSession
                handle(agentSessionId, entryPoint, agentAddress, agentPort, inputRequest, listener)
            | None ->
                let sessionIdStr = sessionId.ToString("X")
                _logger?AgentNotFound(sessionIdStr.TrimStart([|'x'; '0'|]))
                Error(ServerError.AgentNotGeneratedFromThisServer sessionIdStr)

    let newAgentCreatedMessageHandler(sender: Object, message: Envelope<NewAgentCreatedMessage>) =        
        let sessionId = Utility.customFnv1a32Hash(message.Item.PublicKey)
        use agentRepository = new ObjectRepository<AgentSessionDto>()
        match agentRepository.Get(sessionId.ToString("X")) with        
        | Some _ -> ()
        | None -> 
            let agentSession = new AgentSession(message.Item.PrivateKey, message.Item.Settings, messageBroker, logProvider)
            let agentSessionDto = 
                new AgentSessionDto(
                    Id = sessionId.ToString("X"),
                    AgentId = message.Item.AgentId,
                    PrivateKey = Convert.ToBase64String(message.Item.PrivateKey),
                    Settings = message.Item.Settings.ToJson()
                )
            agentRepository.Upsert(new DbEntity<AgentSessionDto>(agentSessionDto, Id = agentSessionDto.Id))
            _sessions.[sessionId] <- agentSession            

    let agentTerminatedMessageHandler(sender: Object, message: Envelope<AgentTerminatedMessage>) =
       _sessions
       |> Seq.tryFind(fun kv -> kv.Value.Id = message.Item.AgentId)
       |> function
        | Some kv -> 
            _sessions.Remove(kv.Key) |> ignore
            kv.Value.Dispose()
        | None -> ()

    do
        messageBroker.Subscribe(this, newAgentCreatedMessageHandler)
        messageBroker.Subscribe(this, agentTerminatedMessageHandler)

    member this.HandleAgentRequest
        (
            sessionId: String, 
            entryPoint: String, 
            agentAddress: String, 
            agentPort: Int32, 
            inputRequest: Byte array,
            listener: IListener
        ) =
        lock _syncRoot (fun () ->
            try
                handle(sessionId, entryPoint, agentAddress, agentPort, inputRequest, listener)
            with e ->
                Error(ServerError.ProcessingException(e.ToString()))
        )