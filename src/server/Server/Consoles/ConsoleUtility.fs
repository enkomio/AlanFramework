namespace ES.Alan.Server.Consoles

open System
open System.Text
open System.Collections.Generic
open ES.Alan.Core.Entities
open System.IO
open System.Reflection.PortableExecutable
open System.Reflection
open ES.Alan.Core

module ConsoleUtility =
    let mutable _messageBroker: MessageBroker option = None

    let setMessageBroker(messageBroker: MessageBroker) =
        _messageBroker <- Some messageBroker

    let readText() =
        let line = Console.ReadLine()
        _messageBroker
        |> Option.iter(fun mb -> mb.Dispatch(mb, new InputTextMessage(line + Environment.NewLine)))
        line

    let writeText(text: Object) =
        _messageBroker
        |> Option.iter(fun mb -> mb.Dispatch(mb, new InputTextMessage(text.ToString())))
        Console.Write(text)

    let writeLineText(text: Object) =
        let safeText = if isNull text then String.Empty else text.ToString()        
        writeText(safeText + Environment.NewLine)

    let read(text: String) =
        writeText(String.Format("{0}: ", text.Trim([|' '; ':'|])))
        readText()

    let readWithDefault(text: String, defaultValue: String) =
        let fullText = String.Format("{0} [{1}]", text, defaultValue)
        let inputValue = read(fullText)
        if String.IsNullOrWhiteSpace(inputValue) then defaultValue
        else inputValue 

    let readWithConstraints(text: String, acceptedValues: String array) =
        let acceptedValuesLower = acceptedValues |> Array.map(fun v -> v.ToLower())
        let fullText = String.Format("{0} ({1})", text, String.Join('/', acceptedValues))
        let mutable inputValue = readWithDefault(fullText, acceptedValues.[0])
        while acceptedValuesLower |> Array.contains (inputValue.ToLower()) |> not do
            inputValue <- readWithDefault(fullText, acceptedValues.[0])
        inputValue

    let getBitness(bitness: String, fileContent: Byte array, defaultBitness: CpuBitness) =
        if bitness.Equals("x86", StringComparison.OrdinalIgnoreCase) then 
            CpuBitness.Bitness32
        elif bitness.Equals("x86", StringComparison.OrdinalIgnoreCase) then 
            CpuBitness.Bitness32
        elif fileContent.[0] = byte 'M' && fileContent.[1] = byte 'Z' then
            CpuBitness.FromPeContent(fileContent)
        else
            defaultBitness

    let normalizePath(rawPath: String) =
        let path = rawPath |> Environment.ExpandEnvironmentVariables
        if Path.IsPathRooted(path) then 
            path |> Path.GetFullPath
        else
            let curPath = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location)
            Path.Combine(curPath, path) |> Path.GetFullPath

    let parseArguments(argString: String) =        
        let sb = new StringBuilder()
        let mutable skip = false
        let mutable inString = false

        [|
            for c in argString do  
                if inString then
                    // only the " character can be skipped when 
                    // inside a double quoted string
                    if skip then
                        if c <> '"' then
                            sb.Append('\\') |> ignore                        
                        sb.Append(c) |> ignore
                        skip <- false
                    elif c = '\\' then
                        skip <- true
                    elif c = '"' then
                        inString <- false
                        yield sb.ToString()
                        sb.Clear() |> ignore
                    else
                        sb.Append(c) |> ignore
                elif c = '"' then
                    inString <- true
                elif c = ' ' then
                    if sb.Length > 0 then
                        yield sb.ToString()
                    sb.Clear() |> ignore
                else
                    sb.Append(c) |> ignore

            if sb.Length > 0 then
                yield sb.ToString()
        |]    

type ConsoleTable(columns: String array) =
    let _rows = new List<Object array>()

    member this.AddRow(row: Object array) =
        let splittedRows = row |> Array.map(fun item -> item.ToString().Split(Environment.NewLine))
        let longestRow = splittedRows |> Array.map(fun r -> r.Length) |> Array.max

        for i=0 to longestRow-1 do
            let innerRow = [|   
                for j=0 to row.Length-1 do
                    let splittedRow = splittedRows.[j]                    
                    yield 
                        if i < splittedRow.Length then splittedRow.[i]
                        else String.Empty
                        |> box
            |]
            _rows.Add(innerRow)        

    override this.ToString() =
        let columnSize = Array.zeroCreate<Int32>(columns.Length)
        let separator = new StringBuilder()
        let formatStringBuilder = new StringBuilder("|")
                
        columns
        |> Seq.iteri(fun i columnName ->
            let maxLength =
                if _rows.Count > 0 then
                    _rows                    
                    |> Seq.map(fun row -> max (row.[i].ToString().Length) columns.[i].Length)
                    |> Seq.max
                else
                    columns.[i].Length

            columnSize.[i] <- maxLength
            separator.Append("+").Append("-".PadLeft(maxLength+1, '-')) |> ignore
            formatStringBuilder.AppendFormat("{{{0}, -{1}}} |", i, maxLength) |> ignore
        )
        separator.Append("+") |> ignore

        // compose table
        let table = new StringBuilder()
        table
            .AppendLine(separator.ToString())
            .AppendLine(String.Format(formatStringBuilder.ToString(), columns |> Seq.cast<Object> |> Seq.toArray))
            .AppendLine(separator.ToString())
            |> ignore
        _rows
        |> Seq.iter(fun row ->
            table.AppendLine(String.Format(formatStringBuilder.ToString(), row)) |> ignore
        )
        table.AppendLine(separator.ToString()) |> ignore
        table.ToString()