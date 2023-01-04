# Crassus Windows privilege escalation

## Why "Crassus"?

Accenture made a tool called [Spartacus](https://github.com/Accenture/Spartacus), which finds DLL hijacking opportunities on Windows. Using Spartacus as a starting point, we created Crassus to extend Windows privilege escalation finding capabilites beyond simply looking for missing files. The ACLs used by files and directories of privileged processes can find more than just [looking for missing files](https://vuls.cert.org/confluence/display/Wiki/2021/06/21/Finding+Privilege+Escalation+Vulnerabilities+in+Windows+using+Process+Monitor) to achieve the goal.

## Did you really make yet another privilege escalation discovery tool?

...but with a twist as Crassus is utilising the [SysInternals Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) and is parsing raw PML log files. You can leave ProcMon running for hours and discover 2nd and 3rd level (ie an app that loads another DLL that loads yet another DLL when you use a specific feature of the parent app) DLL Hijacking vulnerabilities. It will also automatically generate proxy DLLs with all relevant exports for vulnerable DLLs.

## Features

* Parsing ProcMon PML files natively. The log (PML) parser has been implemented by porting partial functionality to C# from https://github.com/eronnen/procmon-parser/. You can find the format specification [here](https://github.com/eronnen/procmon-parser/tree/master/docs).
* Crassus will create proxy DLLs for all missing DLLs that were identified. For instance, if an application is vulnerable to DLL Hijacking via `version.dll`, Crassus will create a `version.dll.cpp` file for you with all the exports included in it. Then you can insert your payload/execution technique and compile.
* Able to process large PML files and store all DLLs of interest in an output CSV file. Local benchmark processed a 3GB file with 8 million events in 45 seconds.

# Table of Contents

* [Screenshots](#screenshots)
    * [Crassus Execution](#Crassus-execution)
    * [CSV Output](#csv-output)
    * [Exports](#output-exports)
    * [Export DLL Functions](#export-dll-functions)
* [Usage](#usage)
    * [Execution Flow](#execution-flow)
    * [Command Line Arguments](#command-line-arguments)
    * [Examples](#examples)
    * [Proxy DLL Template](#proxy-dll-template)
* [Contributions](#contributions)
* [Credits](#credits)

# Screenshots

## Crassus Execution

![Running Crassus](screenshots/runtime.png "Running Crassus")

## CSV Output

![CSV Output](screenshots/output.png "CSV Output")

## Output Exports

![Exports](screenshots/exports.png "Exports")

## Export DLL Functions

![DLL Functions](screenshots/exports-version.png "DLL Functions")

# Usage

## Execution Flow

1. Generate a ProcMon (PMC) config file on the fly, based on the arguments passed. The filters that will be set are:
    * Operation is `CreateFile`.
    * Path ends with `.dll`.
    * Process name is not `procmon.exe` or `procmon64.exe`.
    * Enable `Drop Filtered Events` to ensure minimum PML output size.
    * Disable `Auto Scroll`.
2. Execute Process Monitor.
3. Halt its execution until the user presses `ENTER`.
4. Terminates Process Monitor.
5. Parses the output Event Log (PML) file.
    1. Creates a CSV file with all the NAME_NOT_FOUND and PATH_NOT_FOUND DLLs.
    2. Compares the DLLs from above and tries to identify the DLLs that were actually loaded.
    3. For every "found" DLL it generates a proxy DLL with all its export functions.

## Command Line Arguments

| Argument                  | Description |
| ------------------------- | ----------- |
| `--pml`                   | Location (file) to store the ProcMon event log file. If the file exists, it will be overwritten. When used with `--existing-log` it will indicate the event log file to read from and will not be overwritten. |
| `--verbose`               | Enable verbose output. |
| `--debug`                 | Enable debug output. |

## Examples

Collect all events and save them into `C:\Data\logs.pml`. All vulnerable DLLs will be saved as `C:\Data\VulnerableDLLFiles.csv` and all proxy DLLs in `C:\Data\DLLExports`.

```
--procmon C:\SysInternals\Procmon.exe --pml C:\Data\logs.pml --csv C:\Data\VulnerableDLLFiles.csv --exports C:\Data\DLLExports --verbose
```

Collect events only for `Teams.exe` and `OneDrive.exe`.

```
--procmon C:\SysInternals\Procmon.exe --pml C:\Data\logs.pml --csv C:\Data\VulnerableDLLFiles.csv --exports C:\Data\DLLExports --verbose --exe "Teams.exe,OneDrive.exe"
```

Collect events only for `Teams.exe` and `OneDrive.exe`, and use a custom proxy DLL template at `C:\Data\myProxySkeleton.cpp`.

```
--procmon C:\SysInternals\Procmon.exe --pml C:\Data\logs.pml --csv C:\Data\VulnerableDLLFiles.csv --exports C:\Data\DLLExports --verbose --exe "Teams.exe,OneDrive.exe" --proxy-dll-template C:\Data\myProxySkeleton.cpp
```

Collect events only for `Teams.exe` and `OneDrive.exe`, but don't generate proxy DLLs.

```
--procmon C:\SysInternals\Procmon.exe --pml C:\Data\logs.pml --csv C:\Data\VulnerableDLLFiles.csv --verbose --exe "Teams.exe,OneDrive.exe"
```

Parse an existing PML event log output, save output to CSV, and generate proxy DLLs.

```
--existing-log --pml C:\MyData\SomeBackup.pml --csv C:\Data\VulnerableDLLFiles.csv --exports C:\Data\DLLExports
```

Run in monitoring mode and try to detect any applications that is proxying DLL calls.

```
--detect
```

## Proxy DLL Template

Below is the template that is used when generating proxy DLLs, the generated `#pragma` statements are inserted by replacing the `%_PRAGMA_COMMENTS_%` string.

The only thing to be aware of is that the `pragma` DLL will be using a hardcoded path of its location rather than trying to load it dynamically.

```cpp
#pragma once

%_PRAGMA_COMMENTS_%

#include <windows.h>
#include <string>
#include <atlstr.h>  

VOID Payload() {
    // Run your payload here.
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        Payload();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

If you wish to use your own template, just make sure the `%_PRAGMA_COMMENTS_%` is in the right place.

# Contributions
Whether it's a typo, a bug, or a new feature, Crassus is very open to contributions as long as we agree on the following:
* You are OK with the MIT license of this project.
* Before creating a pull request, create an issue so it could be discussed before doing any work as internal development is not tracked via the public GitHub repository. Otherwise you risk having a pull request rejected if for example we are already working on the same/similar feature, or for any other reason.

# Credits

* https://github.com/eronnen/procmon-parser/
