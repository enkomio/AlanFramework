namespace ES.Alan.Server

open System
open System.IO
open System.Reflection
open ES.Fslog
open ES.Fslog.Loggers
open Autofac
open ES.Alan.Core
open ES.Alan.Server.Consoles
open ES.Alan.Server
open System.Net
open System.Net.Sockets
open System.Diagnostics
open Argu
open System.IO.Pipes
open System.Text

module Program =
    type CLIArguments =
        | Version 
        | Verbose        
    with
        interface IArgParserTemplate with
            member s.Usage =
                match s with                
                | Version -> "display Taipan version."
                | Verbose -> "print verbose messages."

    let private version() =
        let location = Assembly.GetExecutingAssembly().Location        
        let vi = FileVersionInfo.GetVersionInfo(location)
        if vi <> null then vi.FileVersion
        else Assembly.GetExecutingAssembly().GetName().Version.ToString()
    
    let private _logger =
        log "Program"
        |> info "Version" "Alan version: {0}"
        |> info "StartListener" "Start listeners"        
        |> build

    let private logIPs() =
        Dns.GetHostAddresses(Dns.GetHostName())
        |> Array.filter(fun ip -> ip.AddressFamily = AddressFamily.InterNetwork)
        |> Array.iter(fun ip -> _logger?IPAddress(ip))        

    let private printBanner() =
        // from https://fsymbols.com/generators/carty/
        let logo = """
 ░█████╗░██╗░░░░░░█████╗░███╗░░██╗
 ██╔══██╗██║░░░░░██╔══██╗████╗░██║
 ███████║██║░░░░░███████║██╔██╗██║
 ██╔══██║██║░░░░░██╔══██║██║╚████║
 ██║░░██║███████╗██║░░██║██║░╚███║
 ╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝╚═╝░░╚══╝"""

        let padding(s: String) = 
            logo.Split() 
            |> Array.map(fun l -> l.Length)
            |> Array.max
            |> fun len -> 
                let paddingLength = (Math.Abs(s.Length - len - 2) / 2)
                let padding = String.replicate paddingLength " "
                let resultString = padding + s + padding
                if resultString.Length < len then resultString + " "
                else resultString

        let printColor(text: String, color: ConsoleColor) =
            Console.BackgroundColor <- color
            Console.Write(text)
            Console.ResetColor()
            Console.WriteLine()

        Console.WriteLine(logo)                
        printColor(padding("-=[ Post Exploitation Framework ]=-"), ConsoleColor.DarkRed)
        let yearNum = DateTime.Now.Year
        let year = if yearNum = 2021 then "2021" else String.Format("2021-{0}", yearNum)
        let copy = String.Format("Copyright (c) {0} Enkomio", year)        
        
        printColor(padding(copy),  ConsoleColor.DarkBlue)
        Console.WriteLine()    

    let private configureContainer(logProvider: ILogProvider) =
        let builder = new ContainerBuilder()
        ignore(            
            builder.RegisterType<Listeners.HttpListener>().SingleInstance(),
            builder.RegisterType<Listeners.HttpsListener>().SingleInstance(),
            builder.RegisterType<ProxyStorage>().SingleInstance(),
            builder.RegisterType<EvidenceLogger>().SingleInstance(),
            builder.RegisterType<EndpointRepository>().SingleInstance(),
            builder.RegisterType<AgentService>().SingleInstance(),
            builder.RegisterType<CliConsole>().SingleInstance(),
            builder.RegisterType<MessageBroker>().SingleInstance(),
            builder.RegisterType<NetworkUtility>().SingleInstance(),
            builder.RegisterInstance(logProvider).As<ILogProvider>()
        )
        builder.Build()

    let private configureLogProvider(isVerbose: Boolean) =
        let logProvider = new LogProvider()
        let logLevel = if isVerbose then LogLevel.Verbose else LogLevel.Informational
        logProvider.AddLogger(new ConsoleLogger(logLevel))
        let logFileName = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "alan.log")
        logProvider.AddLogger(new FileLogger(logLevel, logFileName))
        logProvider

    [<EntryPoint>]
    let main argv =
        printBanner()  
        let parser = ArgumentParser.Create<CLIArguments>()
        try            
            let results = parser.Parse(argv)
                    
            if results.IsUsageRequested then
                Console.WriteLine(parser.PrintUsage())
                0
            elif results.Contains(<@ Version @>) then
                Console.WriteLine("Version: {0}", version()) 
                0
            else
                let isVerbose = results.Contains(<@ Verbose @>)
                let logProvider = configureLogProvider(isVerbose)
                logProvider.AddLogSourceToLoggers(_logger)
                use container = configureContainer(logProvider)        
                _logger?Version(version())
                _logger?StartListener()

                // SSL settings
                ServicePointManager.SecurityProtocol <- SecurityProtocolType.Tls11 ||| SecurityProtocolType.Tls12 ||| SecurityProtocolType.Tls13
                ServicePointManager.CheckCertificateRevocationList <- false
                ServicePointManager.ServerCertificateValidationCallback <- new Security.RemoteCertificateValidationCallback(fun a b c d -> true)

                // start proxy storage
                use proxyStorage = container.Resolve<ProxyStorage>()
                proxyStorage.Start()

                // start evidence logger
                let evidenceLogger = container.Resolve<EvidenceLogger>()
                ConsoleUtility.setMessageBroker(container.Resolve<MessageBroker>())
                evidenceLogger.Start()

                // start listeners
                use httpListener = container.Resolve<Listeners.HttpListener>()
                httpListener.Start()

                use httpsListener = container.Resolve<Listeners.HttpsListener>()
                httpsListener.Start()

                // start console
                let cliConsole = container.Resolve<CliConsole>()
                cliConsole.Start()
                0
        with 
        | :? ArguParseException ->
            ConsoleUtility.writeLineText(parser.PrintUsage())   
            1
        | e ->
            ConsoleUtility.writeLineText(e.ToString())
            1
