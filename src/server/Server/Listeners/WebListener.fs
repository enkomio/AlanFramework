namespace ES.Alan.Server.Listeners

open System
open System.Collections.Generic
open System.Threading
open System.Threading.Tasks
open System.Text
open System.Net
open System.IO
open System.Globalization
open System.Reflection
open Suave
open Suave.Successful
open Suave.Writers
open Suave.Files
open Suave.Cookie
open Suave.Redirection
open Suave.Operators
open Suave.Filters
open Suave.RequestErrors
open ES.Fslog
open ES.Alan.Core
open ES.Alan.Core.Entities
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Security
open Org.BouncyCastle.X509
open Org.BouncyCastle.Math
open Org.BouncyCastle.Asn1.X509
open Org.BouncyCastle.Asn1.Sec
open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Operators
open Org.BouncyCastle.Asn1.X9
open System.Security.Cryptography.X509Certificates
open Org.BouncyCastle.Pkcs
open System.Security
open Org.BouncyCastle.Asn1.Pkcs
open Suave.Sockets
open Suave.Sockets.Control
open System.Net.Security
open System.Security.Authentication

[<AbstractClass>]
type WebListener(agentService: AgentService, messageBroker: MessageBroker, endpointRepository: EndpointRepository, listenerType: ListenerType, logProvider: ILogProvider) as this =
    let _endPoints = new List<Endpoint>()

    let _logger =
        log "WebListener"
        |> verbose "EndpointNotDefined" "Received connection on undefined endpoint: {0}"
        |> verbose "EndpointError" "Error '{0}', on endpoint: {1}"
        |> verbose "EndpointRemoved" "Removed endpoint '{0}' for session cookie: {1}"
        |> verbose "EndpointAdded" "Added new endpoint '{0}' with session cookie: {1} for agent ID: {2}"
        |> info "Started" "Web listener started on: {0}:{1}"
        |> buildAndAdd(logProvider)
    
    let postFilter (ctx: HttpContext) = async {                
        return Some ctx
    }            

    let preFilter (ctx: HttpContext) = async {
        return Some ctx
    }    

    let log (ctx: HttpContext) = async {
        return Some ctx
    }        

    let tryGetEndpoint(ctx: HttpContext) =
        _endPoints
        |> Seq.map(fun endpoint ->
            match ctx.request.cookies.TryGetValue endpoint.SessionCookieName with
            | (true, cookie) -> Some(endpoint, cookie)
            | _ -> None
        )
        |> Seq.tryHead

    let addHeaders(headers: List<Header>) = 
        headers 
        |> Seq.toArray
        |> Array.fold(fun s h -> (addHeader h.Name h.Value) >=> s) WebPart.succeed
        
    let generateSuccessResponse(data: String) =                
        OK data
        >=> addHeaders (this.GetSettings().SuccessRequest.Headers)

    let generateErrorResponse =                
        fun () ->
            match HttpCode.tryParse(this.GetSettings().ErrorRequest.StatusCode) with
            | Choice1Of2 httpCode -> 
                let responseBody = Encoding.UTF8.GetBytes(this.GetSettings().ErrorRequest.Html)
                Response.response httpCode responseBody
                >=> addHeaders (this.GetSettings().ErrorRequest.Headers)
            | _ -> 
                NOT_FOUND (this.GetSettings().ErrorRequest.Html)
                >=> addHeaders (this.GetSettings().ErrorRequest.Headers)

    let agentRequest (ctx: HttpContext) =        
        match tryGetEndpoint(ctx) with
        | Some(Some(endpoint, cookie)) -> 
            // endpoint found proceeds to handle the request
            agentService.HandleAgentRequest(
                cookie.value, 
                ctx.request.path, 
                ctx.connection.ipAddr.ToString(), 
                int32 ctx.connection.port,
                ctx.request.rawForm,
                downcast this
            ) |> function
            | Ok resultMsg ->
                let resultData = Encoding.UTF8.GetString(resultMsg)
                let finalData = 
                    this.GetSettings().SuccessRequest.Prepend + 
                    resultData + 
                    this.GetSettings().SuccessRequest.Append
                generateSuccessResponse(finalData) ctx
            | Error errorCode -> 
                _logger?EndpointError(errorCode, ctx.request.url.PathAndQuery)
                generateErrorResponse() ctx
        | _ -> 
            _logger?EndpointNotDefined(ctx.request.url.PathAndQuery)
            generateErrorResponse() ctx

    let _routes =
        [
            POST >=> preFilter >=> choose [ 
                pathScan "/%s" (fun _ -> agentRequest)
            ] >=> log >=> postFilter

            GET >=> preFilter >=> choose [ 
                pathScan "/%s" (fun _ -> agentRequest)
            ] >=> log >=> postFilter
        ]
        |> choose

    abstract GetSuaveConfig: unit -> SuaveConfig    
    abstract GetCancellationTokenSource: unit -> CancellationTokenSource
    abstract GetSettings: unit -> WebListenerSettings
    abstract GetListenerType: unit -> ListenerType

    member this.Address 
        with get() = this.GetSettings().BindingIp

    member this.Port
        with get() = this.GetSettings().BindingPort

    member this.Start() =   
        endpointRepository.Query(fun _ -> true)
        |> Seq.iter(_endPoints.Add)

#if DEBUG
        let newEndpoint = {
            Id = 123
            AgentId = 1234567890u
            SessionCookieName = "SSID"
            Entrypoint = "/debug"
        }
        _endPoints.Add(newEndpoint)
#endif

        let processSettings(agentId: UInt32, settings: AgentSettings) =
            let hasHttpServers = settings.Servers.Http.Count > 0
            let hasHttpsServers = settings.Servers.Https.Count > 0

            if 
                (hasHttpServers && this.GetListenerType() = ListenerType.Http) || 
                (hasHttpsServers && this.GetListenerType() = ListenerType.Https) 
            then
                // remove endpoints if already defined
                _endPoints
                |> Seq.tryFind(fun endpoint -> endpoint.AgentId = agentId)
                |> function
                    | Some endpoint -> 
                        _endPoints.Remove(endpoint) |> ignore
                        _logger?EndpointRemoved(endpoint.Entrypoint, endpoint.SessionCookieName)
                    | None -> ()
                
                // update endpoints
                [
                    settings.Servers.Http
                    settings.Servers.Https
                ]
                |> Seq.concat
                |> Seq.iter(fun http ->
                    _endPoints
                    |> Seq.tryFind(fun endpoint -> 
                        endpoint.SessionCookieName.Equals(http.Request.SessionCookie) &&
                        endpoint.Entrypoint.Equals(http.Request.Path)
                    )
                    |> function
                        | None -> 
                            let newEndpoint = {
                                Id = _endPoints.Count + 1
                                AgentId = agentId
                                SessionCookieName = http.Request.SessionCookie                                
                                Entrypoint = http.Request.Path
                            }
                            _endPoints.Add(newEndpoint)
                            endpointRepository.Upsert(new DbEntity<Endpoint>(newEndpoint, Id = newEndpoint.Id.ToString("X")))
                            let fullEndpoint = String.Format("{0}://{1}:{2}{3}", this.GetListenerType(), http.Address, http.Port, newEndpoint.Entrypoint)
                            _logger?EndpointAdded(fullEndpoint, newEndpoint.SessionCookieName, agentId.ToString("X"))
                        | _ -> ()
                )

        let newAgentCreatedMessageHandler(sender: Object, message: Envelope<NewAgentCreatedMessage>) =
            processSettings(message.Item.AgentId, message.Item.Settings)

        let agentTerminatedMessageHandler(sender: Object, message: Envelope<AgentTerminatedMessage>) =
            _endPoints
            |> Seq.tryFind(fun endPoint -> endPoint.AgentId = message.Item.AgentId)
            |> Option.iter(fun endpoint -> _endPoints.Remove(endpoint) |> ignore)            
            endpointRepository.Delete(message.Item.AgentId.ToString("X"))

        let updateConfigMessageHandler(sender: Object, message: Envelope<UpdateConfigMessage>) =
            let newAgentSettings = AgentSettings.Read(message.Item.Settings)
            processSettings(message.Item.AgentId, newAgentSettings)

        let getListenersMessageHandler(sender: Object, message: Envelope<GetEndpointsMessage>) =
            let settings = this.GetSettings()
            if _endPoints.Count > 0 then
                _endPoints
                |> Seq.iter(fun endpoint ->
                    message.Item.Endpoints.Add({
                        BindingIp = settings.BindingIp
                        BindingPort = settings.BindingPort
                        Type = this.GetListenerType()
                        Entrypoint = endpoint.Entrypoint
                    })
                )
            else
                message.Item.Endpoints.Add({
                    BindingIp = settings.BindingIp
                    BindingPort = settings.BindingPort
                    Type = this.GetListenerType()
                    Entrypoint = String.Empty
                })                

        messageBroker.Subscribe(this, newAgentCreatedMessageHandler)
        messageBroker.Subscribe(this, agentTerminatedMessageHandler)
        messageBroker.Subscribe(this, updateConfigMessageHandler)
        messageBroker.Subscribe(this, getListenersMessageHandler)
        
        let cfg = this.GetSuaveConfig()
        let settings = this.GetSettings()

        Task.Factory.StartNew(fun () ->    
            try
                _logger?Started(settings.BindingIp, settings.BindingPort)            
                startWebServer cfg _routes
            with | :? OperationCanceledException->
                messageBroker.Unsubscribe(this)
        , TaskCreationOptions.LongRunning)
        |> ignore

    member this.Dispose() =
        this.GetCancellationTokenSource().Cancel(false)
        endpointRepository.Dispose()

    interface IDisposable with
        member this.Dispose() =
            this.Dispose()

    interface IListener with
        member this.Start() =
            this.Start()

        member this.Address
            with get() = this.Address

        member this.Port
            with get() = this.Port

        member this.GetListenerType() =
            this.GetListenerType()

type HttpListener(agentService: AgentService, messageBroker: MessageBroker, endpointRepository: EndpointRepository, logProvider: ILogProvider) =
    inherit WebListener(
        agentService, 
        messageBroker, 
        endpointRepository,        
        ListenerType.Http,
        logProvider
    )
    let _shutdownToken = new CancellationTokenSource()  
    let _settings = WebListenerSettings.Read("http_listener_config.json")  
    
    default this.GetCancellationTokenSource() =
        _shutdownToken

    default this.GetSettings() =
        _settings

    default this.GetSuaveConfig() =
        {defaultConfig with
            bindings = [HttpBinding.create HTTP (IPAddress.Parse _settings.BindingIp) (uint16 _settings.BindingPort)]
            listenTimeout = TimeSpan.FromMilliseconds (float _settings.Timeout)
            cancellationToken = _shutdownToken.Token
            hideHeader = true        
            maxContentLength = 1000000000 // 1GB
            logger = 
                {new Suave.Logging.Logger with 
                    member this.log a b = ()
                    member this.logWithAck a b = async { () }
                    member this.name = Array.empty
                }
        } 
        
    default this.GetListenerType() =
        ListenerType.Http

type MyTlsProvider() = 
    interface TlsProvider with
        member this.wrap(connection : Connection, cert : obj) = socket {
            let sslStream = new SslStream(new TransportStream(connection.transport))  
            try
                sslStream.AuthenticateAsServer(
                    cert :?> X509Certificate, 
                    false, 
                    SslProtocols.Tls13 ||| SslProtocols.Tls12 ||| SslProtocols.Tls11 ||| SslProtocols.Tls,
                    false
                )
            with 
                | :? AuthenticationException as e ->
                    // ignore since it is not a trusted certificate and this behaviour is by design
                    // see: https://github.com/dotnet/runtime/issues/30735
                    ()
            let tlsTransport = new DefaultTlsTransport(connection, sslStream)
            return { connection with transport = tlsTransport }
        }
        
type HttpsListener(agentService: AgentService, messageBroker: MessageBroker, endpointRepository: EndpointRepository, logProvider: ILogProvider) =
    inherit WebListener(
        agentService, 
        messageBroker, 
        endpointRepository,
        ListenerType.Https,
        logProvider
    )
    let _shutdownToken = new CancellationTokenSource()  
    let _settings = WebListenerSettings.Read("https_listener_config.json")  
    let _secureRandom = new SecureRandom()

    let _logger =
        log "HttpsListener"
        |> info "CertificateInfo" "Using certificate: {0}. Expires: {1}"
        |> info "GeneratedCertificate" "Generated new certificate file: {0}"
        |> buildAndAdd logProvider

    let generateRsaKeyPair() =
        let secureRandom = new SecureRandom()
        let keygenParam = new KeyGenerationParameters(secureRandom, 2048)
        let keyGenerator = new RsaKeyPairGenerator()
        keyGenerator.Init(keygenParam)
        keyGenerator.GenerateKeyPair()

    let generateCertificate(issuerPrivate: AsymmetricKeyParameter, subjectPublic: AsymmetricKeyParameter) =
        let notAfter = ref(DateTime.MinValue)
        let parseResult = 
            DateTime.TryParseExact(
                _settings.CA.NotAfter, 
                "yyyy/MM/dd", 
                CultureInfo.InvariantCulture, 
                DateTimeStyles.None, 
                notAfter
            )
        if not parseResult then
            notAfter := DateTime.UtcNow.AddMonths(3)

        let certserial =
            if _settings.CA.Serial = 0 then 
                let rnd = new Random()
                int64 <| rnd.Next()
            else
                int64(_settings.CA.Serial)
                        
        let certGenerator = new X509V3CertificateGenerator()

        // set certificate fields
        let subject = 
            String.Format(
                "CN={0}, OU={1}, O={2}, L={3}, ST={4}, C={5}, E={6}", 
                _settings.CA.Subject.CommonName, 
                _settings.CA.Subject.OrganizationalUnit,
                _settings.CA.Subject.Organization,
                _settings.CA.Subject.Locality,
                _settings.CA.Subject.StateOrProvinceName,
                _settings.CA.Subject.CountryName,
                _settings.CA.Subject.Email
            )
        
        let issuer = 
            String.Format(
                "CN={0}, OU={1}, O={2}, L={3}, ST={4}, C={5}, E={6}", 
                _settings.CA.Issuer.CommonName, 
                _settings.CA.Issuer.OrganizationalUnit,
                _settings.CA.Issuer.Organization,
                _settings.CA.Issuer.Locality,
                _settings.CA.Issuer.StateOrProvinceName,
                _settings.CA.Issuer.CountryName,
                _settings.CA.Issuer.Email
            )
                    
        certGenerator.SetIssuerDN(new X509Name(issuer))
        certGenerator.SetSubjectDN(new X509Name(subject))
        certGenerator.SetSerialNumber(BigInteger.ValueOf(certserial))
        certGenerator.SetNotAfter(!notAfter)
        certGenerator.SetNotBefore(DateTime.UtcNow)
        certGenerator.SetPublicKey(subjectPublic)  
        
        let signatureFactory = new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), issuerPrivate)                
        certGenerator.Generate(signatureFactory)

    let generatePfx(certificate: Org.BouncyCastle.X509.X509Certificate, privateKey: AsymmetricKeyParameter) =
        let certEntry = new X509CertificateEntry(certificate)
        let builder = (new Pkcs12StoreBuilder()).SetUseDerEncoding(true)
        let store = builder.Build()        
        store.SetKeyEntry(
            "certificate", 
            new AsymmetricKeyEntry(privateKey),
            [|certEntry|]
        );
        
        use stream = new MemoryStream()
        store.Save(stream, _settings.CA.Password.ToCharArray(), new SecureRandom())
        Pkcs12Utilities.ConvertToDefiniteLength(stream.ToArray())

    let generateCertificateFile(caFile: String) =
        let caKey = generateRsaKeyPair()
        let eeCert = generateCertificate(caKey.Private, caKey.Public)
        let pfxContent = generatePfx(eeCert, caKey.Private)
        File.WriteAllBytes(caFile, pfxContent)     
        _logger?GeneratedCertificate(caFile)
    
    default this.GetCancellationTokenSource() =
        _shutdownToken

    default this.GetSettings() =
        _settings

    default this.GetSuaveConfig() =   
        let caFile = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), _settings.CAFile)
        if not <| File.Exists(caFile) then
            generateCertificateFile(caFile)
        
        let cert = 
            let tmpCert = new X509Certificate2(File.ReadAllBytes(caFile), _settings.CA.Password)
            if tmpCert.NotAfter < DateTime.Now.AddMonths(1) then
                generateCertificateFile(caFile)
                new X509Certificate2(File.ReadAllBytes(caFile), _settings.CA.Password)
            else
                tmpCert                
        _logger?CertificateInfo(cert.Issuer, cert.GetExpirationDateString())

        {defaultConfig with
            bindings = [HttpBinding.create (HTTPS cert) (IPAddress.Parse _settings.BindingIp) (uint16 _settings.BindingPort)]
            listenTimeout = TimeSpan.FromMilliseconds (float _settings.Timeout)
            cancellationToken = _shutdownToken.Token 
            tlsProvider = new MyTlsProvider()
            hideHeader = true
            maxContentLength = 1000000000 // 1GB
            logger = 
                {new Suave.Logging.Logger with 
                    member this.log a b = ()
                    member this.logWithAck a b = async { () }
                    member this.name = Array.empty
                }
        } 
        
    default this.GetListenerType() =
        ListenerType.Https