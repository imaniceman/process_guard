extern crate winapi;

use log::{error, info};
use std::mem;
use winapi::shared::ntdef::NTSTATUS;
use winapi::um::{
    libloaderapi::{GetModuleHandleW, GetProcAddress},
    sysinfoapi::{GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO},
    winnt::RTL_OSVERSIONINFOW,
};
use wmi::{COMLibrary, WMIConnection};

type RtlGetVersionFn = unsafe extern "system" fn(&mut RTL_OSVERSIONINFOW) -> NTSTATUS;

fn print_os_version() {
    unsafe {
        let ntdll = GetModuleHandleW("ntdll.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr());
        if ntdll.is_null() {
            error!("Failed to load ntdll.dll");
            return;
        }

        let rtl_get_version: RtlGetVersionFn = std::mem::transmute(GetProcAddress(
            ntdll,
            "RtlGetVersion\0".as_ptr() as *const _,
        ));
        if rtl_get_version as usize == 0 {
            info!("Failed to get RtlGetVersion function address");
            return;
        }

        let mut vi: RTL_OSVERSIONINFOW = mem::zeroed();
        vi.dwOSVersionInfoSize = mem::size_of::<RTL_OSVERSIONINFOW>() as u32;
        if rtl_get_version(&mut vi) == 0 {
            info!(
                "Windows Version: {}.{} (Build {})",
                vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber
            );
        } else {
            error!("Failed to get version");
        }
    }
}

fn print_system_info() {
    let mut sys_info: SYSTEM_INFO = unsafe { mem::zeroed() };
    unsafe { GetSystemInfo(&mut sys_info) };
    info!("Number of Processors: {}", sys_info.dwNumberOfProcessors);
    info!("Processor Architecture: {}", unsafe {
        sys_info.u.s().wProcessorArchitecture
    });
}
fn log_memory_status(mem_status: &MEMORYSTATUSEX) {
    const MB: u64 = 1024 * 1024;

    let available_physical_memory = mem_status.ullAvailPhys / MB;
    let total_physical_memory = mem_status.ullTotalPhys / MB;
    let used_physical_memory = total_physical_memory - available_physical_memory;

    // let total_virtual_available_mb = mem_status.ullTotalPageFile / MB - total_physical_memory;
    // let used_virtual_memory_mb = mem_status.ullAvailPageFile / MB;
    // let available_virtual_memory_mb = total_virtual_available_mb - used_virtual_memory_mb;
    let total_virtual_memory_mb = mem_status.ullTotalPageFile / MB;
    let available_virtual_memory_mb = mem_status.ullAvailPageFile / MB;
    let used_virtual_memory_mb = total_virtual_memory_mb - available_virtual_memory_mb;
    info!("Memory Load: {}%", mem_status.dwMemoryLoad);
    info!(
        "Physical Used / Total (MB) : {:>5} / {:>5} , Available {:>5}",
        used_physical_memory, total_physical_memory, available_physical_memory
    );
    info!(
        "Virtual Used / Total  (MB) : {:>5} / {:>5} , Available {:>5}",
        used_virtual_memory_mb, total_virtual_memory_mb, available_virtual_memory_mb
    );
}
pub fn print_memory_status() {
    let mut mem_status = MEMORYSTATUSEX {
        dwLength: mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..unsafe { mem::zeroed() }
    };

    if unsafe { GlobalMemoryStatusEx(&mut mem_status) } != 0 {
        // 物理内存百分比
        log_memory_status(&mem_status);
    } else {
        error!("Failed to retrieve memory status!");
    }
}

fn print_display_driver_version() {
    let com_con = COMLibrary::new().unwrap();
    let wmi_con = WMIConnection::new(com_con).unwrap();
    let results: Vec<std::collections::HashMap<String, wmi::Variant>> = wmi_con
        .raw_query("SELECT DriverVersion FROM Win32_VideoController")
        .unwrap();

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
    use ctor::ctor;
    use log::LevelFilter;
    use log4rs::append::console::ConsoleAppender;
    use log4rs::config::{Appender, Root};
    use log4rs::Config;

    #[ctor]
    fn init_logging() {
        let stdout = ConsoleAppender::builder().build();
        let config = Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .build(Root::builder().appender("stdout").build(LevelFilter::Info))
            .unwrap();

        let _ = log4rs::init_config(config);
    }

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
