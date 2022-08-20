### 7.0 - 01/05/2022
* Implemented `proxy` command for pivoting
* The `info` and `info++` commands display if the agent is using a proxy
* Fixed bug on network communication (Issue 2)
* Fixed error in PE loader when function are import via ordinal
* Fixed JS module causing memory free ahead of time
* Fixed error in `run` command that cause the `&` option to not work
* The log messages are now saved to file `alan.log`
* All the generated output and user input is logged to an evidence file inside the `evidences` folder
* Added machine ID information to `info` command
* Added `Vanilla` package type for agent creation. This allows a better integration of custom packer.

### 6.0.511.28 - 24/02/2022
* x86/x64 PE loaders modified to update the PEB->Ldr field. This allows the system to call DLL_PROCESS_DETACH on the injected DLL.
* Increase max response size to 1GB. This fix the download of big files.
* Added agent expiration date to the configuration.
* The `run` was extended to support the execution of Javascript files.
* `info++` command now shows the Volume label and the FS type.

### 5.0.509.20 - 13/12/2021
* Implemented `run` command
* Implemented `kill` command
* Implemented `exec` command
* Removed `inject` message since it can be achieved with the `run` command in background
* Created stager and PE loader to make the agent stealthier. Each generated agent file has a different hash
* Improved code injection to bypass Dynamic Code Policy Mitigation
* It is now possible to specify the agent file name to create during the wizard
* Fixed error in `upload` and `download` commands
* Fixed error in shell creation. The command shell process token did not have the same agent integrity level
* Removed exported function from DLL agent artifact
* Added current working directory to `info` command
* Extended `shell` command to execute a single command

### 4.0.0 - 27/09/2021
* Added `inject` command. This command allows the operator to inject code into a remote process
* Added `sleep` command performed in short sleep of 400 msec each.
* Introduced Jitter concept in `sleep`
* Ported agent to x64 bit (included PE32+ loader)
* Fixed errors in x86 PE loader
* .NET agent runner is now executed in a stealthier way to avoid detection
* It is now possible to specify a custom Web server in the HTTP/S listener response
* Removed command `listeners` since superfluous 
* Improved `info` command with more information
* Error message are more explanatory
* Added information on process token type (elevated or not)
* Added information on process token privileges
* Added information on process token groups

### 3.0.0 - 15/05/2021
* Renamed agent shell `quit` command to `exit`
* Implemented agent migration via `migrate` command
* Fixed error in retrieving OS version
* Added DLL as agent format in the creation wizard.
* Implemented `ps` command to list the currently running processes
* Implemented `download` command to locally download a file or an entire directory 
* Implemented `upload` command to upload files to the compromised host
* Implemented `SuccessRequest` as HTTP server response option to customize the http/s listener response
* Implemented `ErrorRequest` to customize the http/s listener response for bad requests
* Implemented `prepend` and `append` as HTTP server request option to specify in the agent prof

### 2.0.0 - 20/03/2021
* Implemented agent `detach` command to temporary exit from a joined agent
* Implemented shell `detach` command to temporary exit from a command shell
* Implemented `listeners` command to list the available listeners
* Implemented HTTPS listener to communicatewith the agent via TLS
* Implemented `get-config` command to download the current agent configuration
* Implemented `update` command to update the agent configuration
* Windows7 is now supported

### 1.0.0 - 22/02/2021
* First Release