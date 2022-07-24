namespace ES.Alan.Server.Consoles

open System
open System.Net
open System.Net.Sockets
open ES.Fslog

type NetworkUtility(logProvider: ILogProvider) =
    let _logger =
        log "NetworkUtility"        
        |> info "IPAddress" "Host address: {0}"
        |> info "PublicIP" "External IP: {0}"
        |> buildAndAdd(logProvider)

    let logPrivateIPs() =
        Dns.GetHostAddresses(Dns.GetHostName())
        |> Array.filter(fun ip -> ip.AddressFamily = AddressFamily.InterNetwork)
        |> Array.iter(fun ip -> _logger?IPAddress(ip))  

    let retrievePublicIP() =
        try
            use webClient = new WebClient()
            let publicIP = webClient.DownloadString("https://checkip.amazonaws.com/").Trim()
            NetworkUtility.ExternalIP <- Some publicIP
            _logger?PublicIP(publicIP)
        with _ ->
            ()

    do
        match NetworkUtility.ExternalIP with
        | None -> 
            logPrivateIPs()
            retrievePublicIP()
        | _ -> ()
        
    static member val private ExternalIP = None with get, set

    member this.GetPublicIP() =
        NetworkUtility.ExternalIP