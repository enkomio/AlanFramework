namespace ES.Alan.Server

open System
open ES.Alan.Core
open ES.Alan.Core.Entities

type ProxyDto() =
    member val Id = 0u with get, set
    member val Address = String.Empty with get, set
    member val Port = String.Empty with get, set
    member val Username = String.Empty with get, set
    member val Password  = String.Empty with get, set
    member val ChainProxyId = 0u with get, set

type private ProxyRepository() =
    inherit ObjectRepository<ProxyDto>()

type ProxyStorage(messageBroker: MessageBroker) =
    let _proxyRepository = new ProxyRepository()    
    let mutable _nexIndex = _proxyRepository.Count + 1

    let getNextIndex() =
        _nexIndex <- _nexIndex + 1
        uint32 _nexIndex

    let proxyToDto(proxy: Proxy) =
        new ProxyDto(
            Id = proxy.Id,
            Address = proxy.Address,
            Port = proxy.Port.ToString(),
            Username = proxy.Username,
            Password = proxy.Password,
            ChainProxyId = 
                match proxy.Chain with
                | Some v -> v.Id
                | None -> 0u
        )

    let newProxyMessageHandler(sender: Object, msg: Envelope<NewProxyMessage>) =
        let item = 
            new ProxyDto(
                Id = getNextIndex(),
                Address = msg.Item.Address,
                Port = msg.Item.Port.ToString(),
                Username = msg.Item.Username,
                Password = msg.Item.Password
            )
        msg.Item.CreatedProxyId <- item.Id.ToString()
        _proxyRepository.Upsert(new DbEntity<ProxyDto>(item, Id = item.Id.ToString()))

    let safeToString(x: String) =
        if String.IsNullOrEmpty(x) then String.Empty
        else x

    let rec tryGetChainProxy(proxyDto: ProxyDto) =
        if proxyDto.ChainProxyId > 0u then
            match _proxyRepository.Get(proxyDto.ChainProxyId.ToString()) with
            | Some chainProxyDto ->
                Some(dtoToProxy(chainProxyDto))
            | None ->
                None
        else
            None

    and dtoToProxy(proxyDto: ProxyDto) = {
        Id = proxyDto.Id
        Address = proxyDto.Address |> safeToString
        Port = Utility.int32Parse(proxyDto.Port, 0)
        Username = proxyDto.Username |> safeToString
        Password = proxyDto.Password |> safeToString
        Chain = tryGetChainProxy(proxyDto)
    }

    let getProxiesMessageHandler(sender: Object, msg: Envelope<GetProxiesMessage>) =
        _proxyRepository.Query(fun _ -> true)
        |> Seq.map(dtoToProxy)
        |> msg.Item.Proxies.AddRange

    let tryGetProxyMessage(sender: Object, msg: Envelope<TryGetProxyMessage>) =        
        _proxyRepository.Query(fun proxyDto -> 
            proxyDto.Address.Equals(msg.Item.Address, StringComparison.OrdinalIgnoreCase) &&
            proxyDto.Port.Equals(msg.Item.Port, StringComparison.OrdinalIgnoreCase) &&
            proxyDto.Username.Equals(msg.Item.Username, StringComparison.OrdinalIgnoreCase) &&
            proxyDto.Password.Equals(msg.Item.Password, StringComparison.OrdinalIgnoreCase)
        )
        |> Array.tryHead
        |> function
            | Some proxyDto -> msg.Item.Proxy <- Some <| dtoToProxy(proxyDto)
            | None -> ()

    let createChainProxyMessageHandler(sender: Object, message: Envelope<CreateChainProxyMessage>) =
        let srcProxyDto = _proxyRepository.Get(message.Item.SrcProxy.Id.ToString())
        let dstProxyDto = _proxyRepository.Get(message.Item.DestProxy.Id.ToString())
        match (srcProxyDto, dstProxyDto) with
        | (Some srcProxyDto, Some dstProxyDto) -> 
            srcProxyDto.ChainProxyId <- dstProxyDto.Id
            _proxyRepository.Upsert(new DbEntity<ProxyDto>(srcProxyDto, Id = srcProxyDto.Id.ToString()))
        | _ -> ()

    let deleteProxyMessageHandler(sender: Object, message: Envelope<DeleteProxyMessage>) =
        _proxyRepository.Delete(message.Item.ProxyId.ToString())

    let updateProxyMessage(sender: Object, message: Envelope<UpdateProxyMessage>) =
        let newDtoValue = proxyToDto(message.Item.Proxy)
        _proxyRepository.Upsert(new DbEntity<ProxyDto>(newDtoValue, Id = newDtoValue.Id.ToString()))

    member this.Start() =
        messageBroker.Subscribe(this, newProxyMessageHandler)
        messageBroker.Subscribe(this, getProxiesMessageHandler)
        messageBroker.Subscribe(this, deleteProxyMessageHandler)
        messageBroker.Subscribe(this, createChainProxyMessageHandler)
        messageBroker.Subscribe(this, updateProxyMessage)
        messageBroker.Subscribe(this, tryGetProxyMessage)

    member this.Dispose() =
        _proxyRepository.Dispose()

    interface IDisposable with
        member this.Dispose() =
            this.Dispose()