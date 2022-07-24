namespace ES.Alan.Server.Listeners

open System
open System.Collections.Generic
open System.Reflection
open System.IO
open Newtonsoft.Json

type XName() =
    member val CommonName = String.Empty with get, set
    member val OrganizationalUnit = String.Empty with get, set
    member val Organization = String.Empty with get, set
    member val Locality = String.Empty with get, set
    member val StateOrProvinceName = String.Empty with get, set
    member val CountryName = String.Empty with get, set
    member val Email = String.Empty with get, set

type CA() =
    member val Issuer = new XName() with get, set
    member val Subject = new XName() with get, set
    member val Serial = 0 with get, set
    member val NotAfter = String.Empty with get, set
    member val Password = "Turing" with get, set

type Header() =
    member val Name = String.Empty with get, set
    member val Value = String.Empty with get, set

type ErrorRequest() =
    member val Html = String.Empty with get, set
    member val StatusCode = 404 with get, set
    member val Headers = new List<Header>() with get, set

type SuccessRequest() =
    member val Prepend = String.Empty with get, set
    member val Append = String.Empty with get, set
    member val Headers = new List<Header>() with get, set

type WebListenerSettings() =
    member val BindingIp = "127.0.0.1" with get, set
    member val BindingPort = 8080 with get, set
    member val Timeout = 1000 with get, set
    member val CAFile = "certificate.pfx" with get, set
    member val ErrorRequest = new ErrorRequest() with get, set
    member val SuccessRequest = new SuccessRequest() with get, set
    member val CA = new CA() with get, set
        
    static member Read(fileName: String) =
        let configFile = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "config", fileName)
        let jsonData = File.ReadAllText(configFile)
        JsonConvert.DeserializeObject<WebListenerSettings>(jsonData)