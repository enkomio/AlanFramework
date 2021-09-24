# Alan Framework
Alan Framework is a post-exploitation framework useful during red-team activities. 

**If you find my tool useful, please consider to <a href="https://github.com/sponsors/enkomio">sponsor me</a>.**

You can download the binary from: <a href="https://github.com/enkomio/AlanFramework/releases/latest">https://github.com/enkomio/AlanFramework/releases/latest</a>

## Download

<a href="https://github.com/enkomio/AlanFramework/releases/latest">Download Alan Framework</a>

## Videos: 

* <a href="https://www.youtube.com/watch?v=dgEBEAfEseY">Introduction</a>
* <a href="https://www.youtube.com/watch?v=oLXYUCX7dVY">Update agent profile at runtime</a>
* <a href="https://www.youtube.com/watch?v=L-DVJO7u5Vw">A powerful command-shell and agent migration</a>


## Documentation:
Blog post: <a href="http://antonioparata.blogspot.com/2021/05/alan-post-exploitation-framework.html">http://antonioparata.blogspot.com/2021/05/alan-post-exploitation-framework.html</a>

For more information on its usage please read the <a href="https://github.com/enkomio/AlanFramework/blob/main/doc/Alan%20Documentation%20-%20v3.0.502.19.pdf">documentation</a>.

## Changelog

### 3.0.0 - 15/05/2021
```markdown
- Renamed agent shell `quit` command to `exit`
- Implemented agent migration via `migrate` command
- Fixed error in retrieving OS version
- Added DLL as agent format in the creation wizard.
- Implemented `ps` command to list the currently running processes
- Implemented `download` command to locally download a file or an entire directory 
- Implemented `upload` command to upload files to the compromised host
- Implemented `SuccessRequest` as HTTP server response option to customize the http/s listener response
- Implemented `ErrorRequest` to customize the http/s listener response for bad requests
- Implemented `prepend` and `append` as HTTP server request option to specify in the agent prof
```

### 2.0.500.23 - 20/03/2021
```markdown
- Implemented agent `detach` command to temporary exit from a joined agent
- Implemented shell `detach` command to temporary exit from a command shell
- Implemented `listeners` command to list the available listeners
- Implemented HTTPS listener to communicatewith the agent via TLS
- Implemented `get-config` command to download the current agent configuration
- Implemented `update` command to update the agent configuration
- Windows7 is now supported
```

### 1.0.0 - 22/02/2021
```markdown
- First Release
```
