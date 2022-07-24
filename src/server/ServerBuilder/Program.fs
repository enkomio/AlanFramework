namespace ServerBuilder

open System
open System.Reflection
open System.IO
open Fake.IO
open Fake.DotNet
open Fake.Core
open Fake.Core.TargetOperators

module Program =
    let private _curDir = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location)
 
    // The name of the project
    let project = "Alan Framework"

    // Short summary of the project
    let summary = "A post-exploitation framework."

    // List of author names (for NuGet package)
    let authors = "Enkomio"

    // Extension to not include in release
    let forbiddenExtensions = [".pdb"; ".dev.json"]

    // Read additional information from the release notes document
    let releaseNotesData = 
        let changelogFile = Path.Combine(_curDir, "..", "..", "..", "..", "..", "..", "RELEASE_NOTES.md") |> Path.GetFullPath
        File.ReadAllLines(changelogFile)
        |> ReleaseNotes.parseAll
    
    // The effective Taipan Scanner release version
    let releaseVersion() = 
        let releaseNoteVersion = Version.Parse((List.head releaseNotesData).AssemblyVersion)
        let now = DateTime.UtcNow
        let timeSpan = now.Subtract(new DateTime(1980,2,1,0,0,0))
        let months = timeSpan.TotalDays / 30. |> int32
        let remaining = int32 timeSpan.TotalDays - months * 30
        string <| new Version(releaseNoteVersion.Major, releaseNoteVersion.Minor, months, remaining)    

    let genFSAssemblyInfo (version: String) (projectPath: String) =
        let projectName = Path.GetFileNameWithoutExtension(projectPath)
        let folderName = Path.GetFileName(Path.GetDirectoryName(projectPath))
        let fileName = Path.Combine(folderName, "AssemblyInfo.fs")
        AssemblyInfoFile.createFSharp fileName [ 
            AssemblyInfo.Title projectName
            AssemblyInfo.Product project            
            AssemblyInfo.Guid "E95E7A2F-20A3-4C0A-9C7A-A4644AFB35AA"
            AssemblyInfo.Company authors
            AssemblyInfo.Description summary
            AssemblyInfo.Version version        
            AssemblyInfo.FileVersion version
            AssemblyInfo.InformationalVersion version
        ]

    let extractZipFileToFolder(zipFile: String, destFolder: String) =
        Directory.CreateDirectory(destFolder) |> ignore
        System.IO.Compression.ZipFile.ExtractToDirectory(zipFile, destFolder)

    let releaseFilename = String.Format("Alan.v{0}.zip", releaseVersion())   

    let compile(projectFile: String, buildDir:String, inputProperties: (String * String) list) =
        let projectName = Path.GetFileNameWithoutExtension(projectFile)
        let projectPath = Path.Combine(projectName, projectFile)  
        
        let buildAppDir = Path.Combine(buildDir, projectName)
        Directory.CreateDirectory(buildAppDir) |> ignore

        let defaultProperties = inputProperties @ [
            ("ProductVersion", releaseVersion())
            ("FileVersion", releaseVersion())
            ("AssemblyVersion", releaseVersion())
            ("Satellite_ProductVersion", releaseVersion())
        ] 

        let properties = [("nodeReuse", "False")]    
        
        MSBuild.runReleaseExt id buildAppDir (defaultProperties@properties) "Clean;ReBuild" [projectPath]
        |> Trace.logItems "Build Output: "

    /// Targets
    let createCleanTarget(outDir: String) =
        let buildDir = Path.Combine(outDir, "build")
        let releaseDir = Path.Combine(outDir, "release")
        let debugSymbol = Path.Combine(outDir, "symbols")

        Target.create "Clean" (fun _ ->
            if Directory.Exists(buildDir) then Directory.Delete(buildDir, true)
            if Directory.Exists(releaseDir) then Directory.Delete(releaseDir, true)
            if Directory.Exists(debugSymbol) then Directory.Delete(debugSymbol, true)
            Directory.CreateDirectory(buildDir) |> ignore
            Directory.CreateDirectory(releaseDir) |> ignore
            Directory.CreateDirectory(debugSymbol) |> ignore
        )

    let createAssemblyInfoTarget(sourceDir: String, buildDir: String) =
        Target.create "AssemblyInfo" (fun _ ->
            ["Server"]
            |> List.iter(fun projName ->
                let projFilename = Path.Combine(sourceDir, projName, projName + ".fsproj")
                genFSAssemblyInfo (releaseVersion()) projFilename
            )
        )

    let createCopyClientArtefactsTarget(sourceDir: String, outDir: String) =        
        Target.create "CopyClientArtefacts" (fun _ ->  
            let debugSymbol = Path.Combine(outDir, "symbols")
            let destDirectory = Path.Combine(outDir, "build", "Alan", "resources")
            Directory.CreateDirectory(destDirectory) |> ignore

            [
                // agent files
                ("x86-Release", "agent_exe.exe", "agent32.bin")
                ("x86-Release", "agent_dll.dll", "agent32l.bin")
                ("x64-Release", "agent_exe.exe", "agent64.bin")
                ("x64-Release", "agent_dll.dll", "agent64l.bin")

                // console interceptor files
                ("x64-Release", "console_interceptor_dll.dll", "interceptorx64.bin")
                ("x86-Release", "console_interceptor_dll.dll", "interceptorx86.bin")

                // socks5 proxy
                ("x64-Release", "socks5_exe.exe", "socks5X64.bin")
                ("x86-Release", "socks5_exe.exe", "socks5X86.bin")

                // Exe stager
                ("x64-Release", "pe_packer_exe.exe", "stagerx64.bin")
                ("x86-Release", "pe_packer_exe.exe", "stagerx86.bin")
                ("x64-Release", "pe_packer_dll.dll", "stagerx64l.bin")
                ("x86-Release", "pe_packer_dll.dll", "stagerx86l.bin")
            ]
            |> List.iter(fun (dir, fileName, destFileName) ->
                let fullPath = Path.Combine(sourceDir, "..", "client", "build", dir, fileName) |> Path.GetFullPath
                let fullDestPath = Path.Combine(destDirectory, destFileName) |> Path.GetFullPath                
                Shell.copyFile fullDestPath fullPath
            )

            // copy debug symbols
            ["x86-Release"; "x64-Release"]
            |> List.iter(fun dir ->
                let folder = Path.Combine(sourceDir, "..", "client", "build", dir)
                Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories)  
                |> Array.filter(fun file ->
                    forbiddenExtensions
                    |> List.exists(fun badExtension ->
                        file.EndsWith(badExtension, StringComparison.OrdinalIgnoreCase)
                    )
                )
                |> Array.iter(fun file -> 
                    let destFile = Path.Combine(debugSymbol, Path.GetFileName(file))                
                    File.Move(file, Path.Combine(debugSymbol, destFile))
                    Console.WriteLine("Move {0} to {1}", file, destFile)
                )
            )
            
        )

    let createCompileTarget(outDir: String) =
        let buildDir = Path.Combine(outDir, "build")
        Target.create "Compile" (fun _ ->
            [
                ("x64PELoader.vcxproj", [("Platform", "x64")])
                ("x86PELoader.vcxproj", [("Platform", "x86")])
                ("Server.fsproj", List.empty)
                ("DotNetAgentRunnerX86.csproj", [("Platform", "x86"); ("AllowUnsafeBlocks", "true")])
                ("DotNetAgentRunnerX64.csproj", [("Platform", "x64"); ("AllowUnsafeBlocks", "true")])
            ]
            |> List.iter(fun (projectFile, properties) -> compile(projectFile, buildDir, properties))
        )
        
    let createCopyServerArtefactsTarget(sourceDir: String, outDir: String) =    
        Target.create "CopyServerArtefacts" (fun _ ->            
            let buildDir = Path.Combine(outDir, "build")
            let alanDirectory = Path.Combine(buildDir, "Alan")
            let serverDirectory = Path.Combine(buildDir, "Server")
            let profilesDestDir = Path.Combine(alanDirectory, "profiles")
            let configDestDir = Path.Combine(alanDirectory, "config")
            let resourcesDestDir = Path.Combine(alanDirectory, "resources")

            Directory.CreateDirectory(alanDirectory) |> ignore
            Directory.CreateDirectory(profilesDestDir) |> ignore
            Directory.CreateDirectory(configDestDir) |> ignore
            Directory.CreateDirectory(resourcesDestDir) |> ignore
            let artifactSrcDir = Path.Combine(_curDir, "resources")

            Shell.copyDir alanDirectory serverDirectory FileFilter.allFiles
            Shell.copyFile profilesDestDir (Path.Combine(artifactSrcDir, "agent_default_profile.json"))
            Shell.copyFile configDestDir (Path.Combine(artifactSrcDir, "https_listener_config.json"))
            Shell.copyFile configDestDir (Path.Combine(artifactSrcDir, "http_listener_config.json"))
            Shell.copyFile configDestDir (Path.Combine(artifactSrcDir, "server_config.json"))
            Shell.copyFile resourcesDestDir (Path.Combine(artifactSrcDir, "packaging_powershell_template_x86.ps1"))
            Shell.copyFile resourcesDestDir (Path.Combine(artifactSrcDir, "packaging_powershell_template_x64.ps1"))
            Shell.copyFile (Path.Combine(resourcesDestDir, "DotNetAgentRunnerX64.bin")) (Path.Combine(buildDir, "DotNetAgentRunnerX64", "DotNetAgentRunnerX64.dll"))
            Shell.copyFile (Path.Combine(resourcesDestDir, "DotNetAgentRunnerX86.bin")) (Path.Combine(buildDir, "DotNetAgentRunnerX86", "DotNetAgentRunnerX86.dll"))
            Shell.copyFile (Path.Combine(resourcesDestDir, "x64PELoader.bin")) (Path.Combine(buildDir, "x64PELoader", "x64PELoader.exe"))
            Shell.copyFile (Path.Combine(resourcesDestDir, "x86PELoader.bin")) (Path.Combine(buildDir, "x86PELoader", "x86PELoader.exe"))
            Shell.copyFile (Path.Combine(resourcesDestDir, "wqjsx64.bin")) (Path.Combine(artifactSrcDir, "wqjsx64.exe"))
            Shell.copyFile (Path.Combine(resourcesDestDir, "wqjsx86.bin")) (Path.Combine(artifactSrcDir, "wqjsx86.exe"))

            // copy tools
            let toolDirectory = Path.Combine(alanDirectory, "tools")
            Directory.CreateDirectory(toolDirectory) |> ignore
            Shell.copyFile (Path.Combine(toolDirectory, "cqjsx64.exe")) (Path.Combine(artifactSrcDir, "cqjsx64.exe"))
            Shell.copyFile (Path.Combine(toolDirectory, "cqjsx86.exe")) (Path.Combine(artifactSrcDir, "cqjsx86.exe"))
        )

    let createCleanBuildTarget(outDir: String) =
        let buildDir = Path.Combine(outDir, "build")
        let debugSymbol = Path.Combine(outDir, "symbols")
        Directory.Delete(debugSymbol, true) 
        Directory.CreateDirectory(debugSymbol) |> ignore

        Target.create "CleanBuild" (fun _ ->            
            Directory.GetFiles(buildDir, "*.*", SearchOption.AllDirectories)  
            |> Array.filter(fun file ->
                forbiddenExtensions
                |> List.exists(fun badExtension ->
                    file.EndsWith(badExtension, StringComparison.OrdinalIgnoreCase)
                )
            )
            |> Array.iter(fun file -> 
                let destFile = Path.Combine(debugSymbol, Path.GetFileName(file))                
                File.Move(file, Path.Combine(debugSymbol, destFile))
                Console.WriteLine("Move {0} to {1}", file, destFile)
            )
        )
        
    let createReleaseTarget(outDir: String) =
        Target.create "Release" (fun _ ->
            let buildDir = Path.Combine(outDir, "build")
            let releaseDir = Path.Combine(outDir, "release")
            Directory.CreateDirectory(buildDir) |> ignore
            Directory.CreateDirectory(releaseDir) |> ignore

            Directory.GetFiles(Path.Combine(buildDir, "Alan"), "*.*", SearchOption.AllDirectories)
            |> Fake.IO.Zip.zip (Path.Combine(buildDir, "Alan")) (Path.Combine(releaseDir, releaseFilename))
        )

    let build(sourceDir: String, outDir: String) =      
        Trace.trace("Build Version: " + releaseVersion())
        Trace.trace("Output directory: " + outDir)
        Directory.CreateDirectory(outDir) |> ignore
        
        // create targets
        createCleanTarget(outDir)
        createAssemblyInfoTarget(sourceDir, outDir)
        createCompileTarget(outDir)
        createCleanBuildTarget(outDir)
        createCopyClientArtefactsTarget(sourceDir, outDir)        
        createCopyServerArtefactsTarget(sourceDir, outDir)
        createReleaseTarget(outDir)

        // create build chain
        "Clean"
        ==> "AssemblyInfo"            
        ==> "Compile"                  
        ==> "CleanBuild"  
        ==> "CopyClientArtefacts"
        ==> "CopyServerArtefacts"
        ==> "Release"
        |> Target.runOrDefault 

    let generateFakeContext(workingDir: String) =
        // create the needed Fake context to execute as a program
        let f = Fake.Core.Context.FakeExecutionContext.Create false String.Empty []
        Fake.Core.Context.setExecutionContext(Fake.Core.Context.RuntimeContext.Fake f)        
        Directory.SetCurrentDirectory(workingDir)

    [<EntryPoint>]
    let main argv =        
        let workingDir = Path.Combine(_curDir, "..", "..", "..", "..") |> Path.GetFullPath
        let releaseDir = Path.Combine(workingDir, "..", "..", "..", "Misc", "out") |> Path.GetFullPath
        generateFakeContext(workingDir)
        build(workingDir, releaseDir)
        Console.WriteLine("Release file written at: " + Path.Combine(releaseDir + Path.DirectorySeparatorChar.ToString(), releaseFilename))
        0