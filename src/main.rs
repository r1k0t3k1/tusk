use core::panic;
use core::ffi::c_void;
use std::ffi::CString;

use std::thread::sleep;
use std::time::Duration;

use clap::Parser;

use windows::core::{h, s, w, PCWSTR};
use windows::Win32::System::Antimalware::{AmsiCloseSession, AmsiInitialize, AmsiOpenSession, AmsiScanBuffer, AmsiScanString, AmsiUninitialize, HAMSISESSION};

#[derive(Debug, Parser)]
#[clap(
    name = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS"),
    about = env!("CARGO_PKG_DESCRIPTION"),
    arg_required_else_help = true,
)]
struct Cli {
    #[clap(long = "act", value_name = "ACT", default_value = "1")]
    act: String,
    #[clap(short = 'f', long = "filename", value_name = "FILENAME", required = true)]
    filename: String,
}

//#[link(name = "amsi")]
//#[no_mangle]
//extern "stdcall" {
//	fn AmsiScanBuffer(
//		amsi_context: *const c_void,
//		buf: *const c_void,
//		length: u32,
//		content_name: *const u16,
//		amsi_session: *mut c_void,
//		amsi_result: *mut c_void	
//	) ->  i32;
//}

fn main() {
    let cli = Cli::parse();

    let hamsi_ctx = match unsafe { AmsiInitialize(w!(r"PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.19041.3")) } {
        Ok(ctx) => ctx,
        Err(e) => panic!("Initialize failed: {}", e),
    };

    let amsi_session = match unsafe { AmsiOpenSession(hamsi_ctx) } {
        Ok(session) => session,
        Err(e) => {
            unsafe { AmsiUninitialize(hamsi_ctx) };
            panic!("OpenSession failed: {}", e);
        }
    };

    //let script = h!("Invoke-Mimikatz");
    let script = s!("AMSIScanBuffer");
    let script_ptr= script.as_ptr() as *const c_void;
    
    for i in 1..=unsafe { script.as_bytes().len() } {
        let amsi_result = unsafe { AmsiScanBuffer(hamsi_ctx, script_ptr, i as u32, w!("sample"), amsi_session) };
        println!("{:?}", amsi_result.unwrap());
    }

    unsafe {
        AmsiCloseSession(hamsi_ctx, amsi_session);
        AmsiUninitialize(hamsi_ctx);
    }
}
