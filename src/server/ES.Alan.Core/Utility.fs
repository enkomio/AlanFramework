namespace ES.Alan.Core

open System
open System.IO
open System.Security.Cryptography
open System.Runtime.InteropServices
open Newtonsoft.Json
open PeNet

module Utility =
    let jsonSerialize(data: Object) =
        JsonConvert.SerializeObject(data)

    let customFnv1a32Hash(buffer: Byte array) =
        let fnvp  = 0x01000193u
        let fnvob = 0x811c9dc5u
        let x = uint32(buffer.Length &&& 0xFF)
        let xorKey = x ||| (x <<< 8) ||| (x <<< 16) ||| (x <<< 24)

        buffer
        |> Seq.map(fun b -> uint32 b)
        |> Seq.fold(fun h b ->
            (h ^^^ b) * fnvp
        ) fnvob
        |> fun h -> h ^^^ xorKey

    let computeSha256(data: Byte array) =
        use sha256 = SHA256.Create()
        sha256.ComputeHash(data)

    let private encryptResource(content: Byte array) =
        let key = computeSha256(content)
        let encryptedContent = Array.zeroCreate<Byte>(content.Length)
        let S = seq {0uy..255uy} |> Seq.toArray 

        let swap(i: Int32, j: Int32) =
            let t = S.[i]
            S.[i] <- S.[j]
            S.[j] <- t

        // KSA
        let mutable j = 0uy
        for i=0 to 255 do
            j <- (j + S.[i] + key.[i % key.Length])
            swap(i, int32 j)

        // PRGA
        j <- 0uy
        content
        |> Array.iteri(fun index b ->
            let i = (index + 1) % 256
            j <- j + S.[i]
            swap(i, int32 j)
            let k = S.[int32 <| S.[i] + S.[int32 j]]
            encryptedContent.[index] <- content.[index] ^^^ k
        )
        Array.concat[|key; encryptedContent|]

    let addConfigToAgentFile(agentContent: Byte array, profileContent: Byte array) =
        let encryptedContent = encryptResource(profileContent)
        
        // create the section that will contain the encrypted config        
        let peFile = new PeFile(agentContent)
        let sectionName = ".apiset"        

        if peFile.ImageSectionHeaders |> Seq.exists(fun s -> s.Name.Equals(sectionName, StringComparison.OrdinalIgnoreCase)) then
            peFile.RemoveSection(sectionName)
        peFile.AddSection(sectionName, encryptedContent.Length, Header.Pe.ScnCharacteristicsType.MemRead)
              
        let section = 
            peFile.ImageSectionHeaders 
            |> Seq.find(fun s -> s.Name.Equals(sectionName, StringComparison.OrdinalIgnoreCase))

        use sectionContent = new MemoryStream()
        use binWriter = new BinaryWriter(sectionContent)
        binWriter.Write(encryptedContent)        
        peFile.RawFile.WriteBytes(int64 section.PointerToRawData, sectionContent.ToArray().AsSpan<Byte>())
                
        // writeback the result
        let resultContent = peFile.RawFile.ToArray()
        resultContent

    let generateRandomBuffer(minLength: Int32, maxLength: Int32) =
        let rnd = new Random()
        let length = rnd.Next(minLength, maxLength)
        Array.init length (fun _ -> byte <| rnd.Next(minLength, maxLength))

    let generateRandomString(minLength: Int32, maxLength: Int32) =
        let alphabet =
            Array.init (int Char.MaxValue - int Char.MinValue) char
            |> Array.filter(fun i -> int i < 127)
            |> Array.filter(Char.IsLetterOrDigit)
            
        let rnd = new Random()
        let length = rnd.Next(minLength, maxLength)
        Array.init length (fun _ -> alphabet.[rnd.Next(alphabet.Length)])
        |> fun a -> new String(a)

    let uint32Parse(value: String, defaultValue: UInt32) =
        match UInt32.TryParse value with
        | true, int -> int
        | _ -> defaultValue

    let int32Parse(value: String, defaultValue: Int32) =
        match Int32.TryParse value with
        | true, int -> int
        | _ -> defaultValue