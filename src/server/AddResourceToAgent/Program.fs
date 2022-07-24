open System
open System.IO
open ES.Alan.Core

[<EntryPoint>]
let main argv =
    if argv.Length < 2 then
        Console.WriteLine("Usage: AddResourceToAgent <agent file> <config file>")
        1
    else
        let fullPathAgent = Path.GetFullPath(argv.[0])
        let fullPathProfile = Path.GetFullPath(argv.[1])
        Console.WriteLine("Adding config '{0}' to file: {1}", fullPathProfile, fullPathAgent)
        if not <| File.Exists(fullPathAgent) then
            Console.WriteLine("Agent File {0} NOT FOUND!!!", fullPathAgent)
            3
        elif File.Exists(fullPathProfile) |> not then
            Console.WriteLine("Profile File {0} NOT FOUND!!!", fullPathProfile)
            4
        else
            let newContent = Utility.addConfigToAgentFile(File.ReadAllBytes(fullPathAgent), File.ReadAllBytes(fullPathProfile))
            File.WriteAllBytes(fullPathAgent, newContent)
            0