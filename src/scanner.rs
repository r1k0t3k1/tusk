use core::ffi::c_void;

use windows::core::w;
use windows::Win32::System::Antimalware::{
    AmsiInitialize, 
    AmsiOpenSession,
    AmsiCloseSession,
    AmsiUninitialize,
    AmsiScanBuffer,
    AMSI_RESULT,
    AMSI_RESULT_DETECTED,
    HAMSICONTEXT,
    HAMSISESSION
};

pub struct Scanner {
   amsi_context: HAMSICONTEXT,
   amsi_session: HAMSISESSION
}

impl Scanner {
    pub fn new() -> Self {
    
        let amsi_context = match unsafe { AmsiInitialize(w!(r"PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.19041.3")) } {
            Ok(ctx) => ctx,
            Err(e) => panic!("Initialize failed: {}", e),
        };
    
        let amsi_session = match unsafe { AmsiOpenSession(amsi_context) } {
            Ok(session) => session,
            Err(e) => {
                unsafe { AmsiUninitialize(amsi_context) };
                panic!("OpenSession failed: {}", e);
            }
        };
        
        let scanner = Scanner { amsi_context, amsi_session };

        let Ok(test_result) = scanner.scan(&String::from("Invoke-Mimikatz"), 15) else {
            panic!("[×] AMSI scan failed.");
        };

        if test_result != AMSI_RESULT_DETECTED {
            panic!("[×] AMSI is not working properly.");
        };
        
        scanner
    }

    pub fn scan(&self, script: &String, length: usize) -> Result<AMSI_RESULT, windows_result::Error> {
        let script_ptr= script.as_ptr() as *const c_void;
        let amsi_result = unsafe {
            AmsiScanBuffer(
                self.amsi_context,
                script_ptr,
                length as u32,
                w!("sample"),
                self.amsi_session
            )
        };

        amsi_result
    }
}

impl Drop for Scanner {
	fn drop(&mut self) {
    unsafe {
        AmsiCloseSession(self.amsi_context,self.amsi_session);
        AmsiUninitialize(self.amsi_context);
    }
	}
}

/*

    // chunking
    let script_chunks = script.as_bytes()
        .chunks(cli.chunk_size)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap();

    for chunk in script_chunks {
        let script_ptr= chunk.as_ptr() as *const c_void;

        let mut is_all_clean = true;
        for i in 1..=chunk.len() {
            let amsi_result = unsafe {
                AmsiScanBuffer(
                    hamsi_ctx,
                    script_ptr,
                    i as u32,
                    w!("sample"),
                    amsi_session
                )
            };
            if amsi_result.is_ok() {
                if amsi_result.unwrap() == AMSI_RESULT_DETECTED {
                    is_all_clean = false;
                }
            }
        }

        if is_all_clean {
            print!("{}", chunk);
        } else {
            print!("{}", chunk.red());
        }
    }

    unsafe {
        AmsiCloseSession(hamsi_ctx, amsi_session);
        AmsiUninitialize(hamsi_ctx);
    }
*/
