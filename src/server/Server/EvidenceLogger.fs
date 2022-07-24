namespace ES.Alan.Server

open System
open System.Reflection
open System.IO
open ES.Alan.Core
open ES.Alan.Core.Entities
open ES.Fslog
open ES.Alan.Server.Consoles

type EvidenceLogger(messageBroker: MessageBroker, logProvider: ILogProvider) =
    let _logger =
        log "EvidenceLogger"
        |> info "Start" "Evidence log saved to file: {0}"
        |> buildAndAdd(logProvider)
    
    let _fileName =
        let now = DateTime.Now
        let evidenceFolder = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "evidences")
        Directory.CreateDirectory(evidenceFolder) |> ignore
        let dateFolder = Path.Combine(evidenceFolder, now.ToString("yyyMMdd"))
        Directory.CreateDirectory(dateFolder) |> ignore
        let baseName = Path.Combine(dateFolder, String.Format("session_{0}.txt", now.ToString("hhmm")))
        Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), baseName)

    let inputTextMessageHandler(sender: Object, msg: Envelope<InputTextMessage>) =
        File.AppendAllText(_fileName, msg.Item.Text)

    let outputTextMessageHandler(sender: Object, msg: Envelope<OutputTextMessage>) =
        File.AppendAllText(_fileName, msg.Item.Text)

    member this.Start() =
        _logger?Start(_fileName)
        messageBroker.Subscribe(this, inputTextMessageHandler)
        messageBroker.Subscribe(this, outputTextMessageHandler)
        
