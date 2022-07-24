namespace ES.Alan.Server

open System
open System.IO
open Newtonsoft.Json
open System.Reflection
open ES.Alan.Core

type ServerSettings() =
    member val AgentDllX86File = String.Empty with get, set
    member val AgentExeX86File = String.Empty with get, set
    member val AgentDllX64File = String.Empty with get, set
    member val AgentExeX64File = String.Empty with get, set
    member val x86PeLoader = String.Empty with get, set
    member val x64PeLoader = String.Empty with get, set
    member val ConsoleInterceptorX86 = String.Empty with get, set
    member val ConsoleInterceptorX64 = String.Empty with get, set
    member val DotNetAgentRunnerX86 = String.Empty with get, set    
    member val DotNetAgentRunnerX64 = String.Empty with get, set
    member val JsRunnerX86 = String.Empty with get, set    
    member val JsRunnerX64 = String.Empty with get, set
    member val ExeStagerx86 = String.Empty with get, set
    member val ExeStagerx64 = String.Empty with get, set
    member val DllStagerx86 = String.Empty with get, set
    member val DllStagerx64 = String.Empty with get, set
    member val PowerShellTemplateX86 = String.Empty with get, set
    member val PowerShellTemplateX64 = String.Empty with get, set
    member val ProxyX86 = String.Empty with get, set
    member val ProxyX64 = String.Empty with get, set

    static member val ConfigFile = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "config", "server_config.json") with get, set

    static member Read() =
        let jsonData = File.ReadAllText(ServerSettings.ConfigFile)
        let settings = JsonConvert.DeserializeObject<ServerSettings>(jsonData)
        let baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)
        settings.GetType().GetProperties(BindingFlags.Public ||| BindingFlags.Instance)
        |> Array.iter(fun property ->
            let propertyValue = property.GetValue(settings) :?> String
            if Path.IsPathRooted(propertyValue) |> not then
                let fullPath = Path.Combine(baseDir, propertyValue)
                property.SetValue(settings, fullPath)
        )        
        settings

    member this.MapToPackerSettings() =
        new PackerSettings(
            PeLoaderX86 = this.x86PeLoader,
            PeLoaderX64 = this.x64PeLoader,
            DotNetAgentRunnerFileX86 = this.DotNetAgentRunnerX86,
            DotNetAgentRunnerFileX64 = this.DotNetAgentRunnerX64,
            DllStagerX86 = this.DllStagerx86,
            DllStagerX64 = this.DllStagerx64,
            ExeStagerX86 = this.ExeStagerx86,
            ExeStagerX64 = this.ExeStagerx64,
            PowerShellTemplateX86 = this.PowerShellTemplateX86,
            PowerShellTemplateX64 = this.PowerShellTemplateX64
        )