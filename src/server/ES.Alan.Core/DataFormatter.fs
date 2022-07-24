namespace ES.Alan.Core

open System
open System.IO
open ES.Alan.Core.Entities
open K4os.Compression.LZ4
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Crypto.Parameters
open System.Text
open System.Linq

type DataFormatter() =
    let mutable _iteration = 0u
    let mutable _settings = new AgentSettings()
    let mutable _initialSessionKey = Array.empty<Byte>
    let mutable _sessionId = String.Empty
    let mutable _entryPoint = String.Empty

    let computeSessionKey(iteration: UInt32) =
        let sessionKey = _initialSessionKey |> Array.copy
        
        let v0 = 
            BitConverter.ToUInt32(sessionKey, 0) ^^^ iteration
            |> BitConverter.GetBytes            
        sessionKey.[0] <- v0.[0]
        sessionKey.[1] <- v0.[1]
        sessionKey.[2] <- v0.[2]
        sessionKey.[3] <- v0.[3]
        
        Utility.computeSha256(sessionKey)

    let cleanupData(data: Byte array, listener: IListener) =        
        match listener.GetListenerType() with
        | ListenerType.Http -> 
            _settings.Servers.Http
            |> Seq.tryFind(fun s ->               
                s.Request.Path.Equals(_entryPoint, StringComparison.OrdinalIgnoreCase) &&
                s.Port = listener.Port
            )
            |> function
            | Some s ->                
                data 
                |> Array.skip s.Request.PrependString.Length
                |> Array.take (data.Length - s.Request.PrependString.Length - s.Request.AppendString.Length)
            | None -> data
        | ListenerType.Https ->
            _settings.Servers.Https
            |> Seq.tryFind(fun s ->
                s.Request.Path.Equals(_entryPoint, StringComparison.OrdinalIgnoreCase) &&
                s.Port = listener.Port
            )
            |> function
                | Some s ->
                    data 
                    |> Array.skip s.Request.PrependString.Length
                    |> Array.take (data.Length - s.Request.PrependString.Length - s.Request.AppendString.Length)
                | None -> data
        | _ ->
            data

    member this.Update(settings: AgentSettings, sessionId: String, entryPoint: String) =
        _settings <- settings
        _sessionId <- sessionId
        _entryPoint <- entryPoint

    member this.Initialize(sessionKey: Byte array) = 
        _initialSessionKey <- sessionKey  

    member this.IsDataValid(data: Byte array) =
        if Array.isEmpty data then
            true
        else
            use binReader = new BinaryReader(new MemoryStream(data))
            let inputSha256 = binReader.ReadBytes(32)
            let computedSha256 = Utility.computeSha256(data |> Array.skip 32)
            Enumerable.SequenceEqual(inputSha256, computedSha256)

    member this.Serialize(packets: Packet<AgentCommandType> array) =
        use serializedData = new MemoryStream()
        use binWriter = new BinaryWriter(serializedData)

        // write all the data
        packets
        |> Seq.iter(fun packet ->
            binWriter.Write(int32 packet.Id)
            binWriter.Write(int32 packet.Sequence)
            binWriter.Write(int32 packet.Type)
            binWriter.Write(int32 packet.State)
            binWriter.Write(packet.Data.Length)
            binWriter.Write(packet.Data)
        )

        serializedData.ToArray()

    member this.Deserialize(data: Byte array) =
        use binReader = new BinaryReader(new MemoryStream(data))
        [|
            while(binReader.BaseStream.Position < int64 data.Length) do
                let id = binReader.ReadInt32()
                let sequence = binReader.ReadInt32()
                let dataType = binReader.ReadInt32()
                let dataState = binReader.ReadInt32()
                let dataSize = binReader.ReadInt32()
                yield {
                    Data = binReader.ReadBytes(dataSize)
                    Type = enum<RequestType>(dataType)
                    Id = id
                    State = enum(dataState)
                    Sequence = sequence
                }
        |]

    member this.Encode(data: Byte array, isRegistered: Boolean) =        
        use mutable dataStream = new MemoryStream(data)

        if not isRegistered || _settings.Data.IsCompressed then
            let maxSize = LZ4Codec.MaximumOutputSize(data.Length)
            let compressedData = Array.zeroCreate<Byte>(maxSize)
            let compressedSize = LZ4Codec.Encode(data, 0, data.Length, compressedData, 0, compressedData.Length)             
            use memStream = new MemoryStream()
            use binWriter = new BinaryWriter(memStream)
            binWriter.Write(data.Length)
            binWriter.Write(compressedData |> Array.take compressedSize)
            dataStream <- new MemoryStream(memStream.ToArray())

        if not isRegistered || _settings.Data.IsEncrypted then   
            _iteration <- _iteration + 1u
            let sessionKey = computeSessionKey(_iteration)            

            let chacha = new ChaCha7539Engine()            
            let keyParam = new KeyParameter(sessionKey)
            let iv = Encoding.UTF8.GetBytes(_sessionId.Substring(0, 12))            
            let chachaParams = new ParametersWithIV(keyParam, iv)
            chacha.Init(true, chachaParams)
            let data = dataStream.ToArray()
            let encryptedBytes = Array.zeroCreate<Byte>(data.Length)
            chacha.ProcessBytes(data, 0, data.Length, encryptedBytes, 0)
            let resultBytes = Array.concat <| [|
                Utility.computeSha256(data)
                BitConverter.GetBytes(_iteration)
                encryptedBytes
            |]             
            dataStream <- new MemoryStream(resultBytes)  

        if not isRegistered || _settings.Data.IsBase64Encoded then
            let encodedData = Convert.ToBase64String(dataStream.ToArray())
            dataStream <- new MemoryStream(Encoding.UTF8.GetBytes(encodedData))

        dataStream.ToArray()

    member this.Decode(rawData: Byte array, listener: IListener, isRegistered: Boolean) =
        try
            let data = if isRegistered then cleanupData(rawData, listener) else rawData
            if Array.isEmpty(data) then 
                Array.empty
            else            
                use mutable dataStream = new MemoryStream(data)
                if not isRegistered || _settings.Data.IsBase64Encoded then
                    let base64Data = Encoding.UTF8.GetString(dataStream.ToArray())
                    let decodedData = Convert.FromBase64String(base64Data)
                    dataStream <- new MemoryStream(decodedData)

                if not isRegistered || _settings.Data.IsEncrypted then 
                    use binReader = new BinaryReader(dataStream)
                    let inputSha256 = binReader.ReadBytes(32)
                    let iteration = binReader.ReadUInt32()
                    let clientSessionKey = computeSessionKey(iteration)
                
                    let encryptedBytes = binReader.ReadBytes(int32 dataStream.Length)
                    let chacha = new ChaCha7539Engine()            
                    let keyParam = new KeyParameter(clientSessionKey)
                    let iv = Encoding.UTF8.GetBytes(_sessionId.Substring(0, 12))            
                    let chachaParams = new ParametersWithIV(keyParam, iv)
                    chacha.Init(false, chachaParams)            
                    let decryptedBytes = Array.zeroCreate<Byte>(encryptedBytes.Length)
                    chacha.ProcessBytes(encryptedBytes, 0, encryptedBytes.Length, decryptedBytes, 0)
                    dataStream <- new MemoryStream(decryptedBytes)            

                    // verify integrity
                    let sha256 = Utility.computeSha256(decryptedBytes)                    
                    let integrityOk = Enumerable.SequenceEqual(inputSha256, sha256)
                    if not integrityOk then failwith "Data corrupted"

                if not isRegistered || _settings.Data.IsCompressed then
                    use binReader = new BinaryReader(dataStream)
                    let decompressedLength = binReader.ReadInt32()
                    if decompressedLength > 0 then
                        let compressedData = binReader.ReadBytes(int32 dataStream.Length)
                        let decompressedData = Array.zeroCreate<Byte>(decompressedLength)
                        LZ4Codec.Decode(compressedData, 0, compressedData.Length, decompressedData, 0, decompressedLength) 
                        |> ignore
                        dataStream <- new MemoryStream(decompressedData)

                dataStream.ToArray()
        with _ ->
            Array.empty