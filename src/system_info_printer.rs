extern crate winapi;

use log::error;
use std::mem::{self};
use std::ptr;
use log::info;
use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO, GlobalMemoryStatusEx, MEMORYSTATUSEX};
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
use winapi::um::winnt::{RTL_OSVERSIONINFOW};
use winapi::shared::ntdef::NTSTATUS;
use wmi::{COMLibrary, WMIConnection};
type RtlGetVersionFn = unsafe extern "system" fn(&mut RTL_OSVERSIONINFOW) -> NTSTATUS;
fn print_os_version() {
    unsafe {
        let ntdll = GetModuleHandleW("ntdll.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr());
        if ntdll != ptr::null_mut() {
            let rtl_get_version: RtlGetVersionFn = std::mem::transmute(GetProcAddress(
                ntdll,
                "RtlGetVersion\0".as_ptr() as *const _,
            ));
            if rtl_get_version as usize == 0 {
                info!("Failed to get RtlGetVersion function address");
                return;
            }
            let mut vi: RTL_OSVERSIONINFOW = mem::zeroed();
            let rtl_get_version: RtlGetVersionFn = std::mem::transmute(rtl_get_version);
            vi.dwOSVersionInfoSize = std::mem::size_of::<RTL_OSVERSIONINFOW>() as u32;
            if rtl_get_version(&mut vi) == 0 {
                info!(
                    "Windows Version: {}.{} (Build {})",
                    vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber
                );
            } else {
                error!("Failed to get version");
            }
        } else {
            error!("Failed to load ntdll.dll");
        }
    }
}

fn print_system_info() {
    let mut sys_info: SYSTEM_INFO = unsafe { mem::zeroed() };
    unsafe { GetSystemInfo(&mut sys_info) };
    info!("Number of Processors: {}",   sys_info.dwNumberOfProcessors );
    info!("Processor Architecture: {}", unsafe { sys_info.u.s().wProcessorArchitecture });
}

pub fn print_memory_status() {
    let mut mem_status = MEMORYSTATUSEX {
        dwLength: mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..unsafe { mem::zeroed() }
    };

    if unsafe { GlobalMemoryStatusEx(&mut mem_status) } != 0 {
        info!("Total Physical Memory: {} KB", mem_status.ullTotalPhys / 1024);
        info!("Available Physical Memory: {} KB", mem_status.ullAvailPhys / 1024);
        info!("Total Page File: {} KB", mem_status.ullTotalPageFile / 1024);
        info!("Available Page File: {} KB", mem_status.ullAvailPageFile / 1024);
        info!("Total Virtual Memory: {} KB", mem_status.ullTotalVirtual / 1024);
        info!("Available Virtual Memory: {} KB", mem_status.ullAvailVirtual / 1024);
        info!("Memory Load: {}%", mem_status.dwMemoryLoad);
    } else {
        error!("Failed to retrieve memory status!");
    }
}
fn print_display_driver_version() {
    let com_con = COMLibrary::new().unwrap();
    let wmi_con = WMIConnection::new(com_con).unwrap();
    let results: Vec<std::collections::HashMap<String, wmi::Variant>> = wmi_con.raw_query(
        "SELECT DriverVersion FROM Win32_VideoController"
    ).unwrap();

    for result in results {
        if let Some(wmi::Variant::String(version)) = result.get("DriverVersion") {
            info!("Display driver version: {}", version);
        }
    }
}
pub fn print_all_system_info() {
    print_os_version();
    print_system_info();
    print_memory_status();
    print_display_driver_version();
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_display_driver_version() {
        print_display_driver_version();
    }
    #[test]
    fn test_print_os_version() {
        print_os_version();
    }

    #[test]
    fn test_print_system_info() {
        print_system_info();
    }

    #[test]
    fn test_print_memory_status() {
        print_memory_status();
    }
    #[test]
    fn test_print_all_system_info() {
        print_all_system_info();
    }
}
