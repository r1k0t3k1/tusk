use crate::scanner;

use windows::Win32::System::Antimalware::{AMSI_RESULT, AMSI_RESULT_DETECTED, AMSI_RESULT_NOT_DETECTED};

use colored::Colorize;

const MAX_LEN: u8 = 30;
const MIN_LEN: u8 = 5;

pub fn process(scanner: &scanner::Scanner, script: &String, chunk_size: usize) {
    let Ok(entire_scan_result) = scanner.scan(script, script.len()) else {
        eprintln!("[×] AMSI scan failed.");
        return;
    };

    if entire_scan_result != AMSI_RESULT_DETECTED {
        println!("[-] No malicious scripts were detected.");
        return;
    }

    let script_chunks = script
        .as_bytes()
        .chunks(chunk_size)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap();

    for i in 0..script_chunks.len() {
        let mut script = String::from(script_chunks[i]);
        if i <= script_chunks.len() - 2 {
            script.push_str(script_chunks[i + 1]);
        }
        let Ok(scan_result) = scanner.scan(&script, script.len()) else {
            eprintln!("[×] AMSI scan failed.");
            return;
        };

        if scan_result != AMSI_RESULT_DETECTED { continue; }

        //let mut index = script.len();
        let mut index = 0;

        while index < script.len() {
            if let Some(end) = search_detection_end(&scanner, &script[index..].to_string()) {
               if let Some(start) = search_detection_start(&scanner, &script[index..index+end].to_string()) {
                   println!("{}~{}:{}", start, end, script[index+start..index+end].red());
                   index = index+end;
               } else { return; };
            } else { return; };
        }
       
    }
}

fn search_detection_end(scanner: &scanner::Scanner, script: &String) -> Option<usize> {
    let Ok(scan_result) = scanner.scan(script, script.len()) else {
        eprintln!("[×] AMSI scan failed.");
        return None;
    };

    if scan_result != AMSI_RESULT_DETECTED  { return None; }
    
    for i in (0..script.len()).step_by(5).rev() {
        let Ok(scan_result) = scanner.scan(&script[..i].to_string(), script[..i].len()) else {
            eprintln!("[×] AMSI scan failed.");
            return None;
        };
        
        if scan_result == AMSI_RESULT_DETECTED  { continue; }

        for j in 1..=5 {
            let Ok(scan_result) = scanner.scan(&script[..i+j].to_string(), script[..i+j].len()) else {
                eprintln!("[×] AMSI scan failed.");
                return None;
            };

            if scan_result == AMSI_RESULT_DETECTED  { return Some(i+j); }
        }
    }

    None
}

fn search_detection_start(scanner: &scanner::Scanner, script: &String) -> Option<usize> {
    let Ok(scan_result) = scanner.scan(script, script.len()) else {
        eprintln!("[×] AMSI scan failed.");
        return None;
    };

    if scan_result != AMSI_RESULT_DETECTED  { return None; }
    
    //let sig_length = script.len() < 20 { script.len() } else { script.len() };

    for i in 1..=script.len() {
        let start_index = script.len() - i;

        let Ok(scan_result) = scanner.scan(&script[start_index..].to_string(), i) else {
            eprintln!("[×] AMSI scan failed.");
            return None;
        };

        if scan_result == AMSI_RESULT_DETECTED  { return Some(start_index); }
    }
    None
}

pub fn process_entire_script(scanner: &scanner::Scanner, script: &String) {
    let len = script.len();
    let Ok(result) = scanner.scan(script, len) else {
        eprintln!("[×] AMSI scan failed.");
        return;
    };

    if result == AMSI_RESULT_DETECTED {
        println!("{}", "[+] Malicious scripts were detected.".red());
    }
}

pub fn process_script_per_line(scanner: &scanner::Scanner, script: &String) {
    for (i, l) in script.lines().enumerate() {
        if l.len() == 0 { continue; }
        let Ok(result) = scanner.scan(&l.to_string(), l.len()) else {
            eprintln!("[×] AMSI scan failed.");
            return;
        };

        if result == AMSI_RESULT_DETECTED {
            println!("[+] line {}: {}", i + 1, l.red());
        }
    }
}

pub fn process_script_per_chunk(scanner: &scanner::Scanner, script: &String, chunk_size: usize) {
    let script_chunks = script
        .as_bytes()
        .chunks(chunk_size)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap();

    for (i, c) in script_chunks.iter().enumerate() {
        let Ok(result) = scanner.scan(&c.to_string(), c.len()) else {
            eprintln!("[×] AMSI scan failed.");
            return;
        };

        if result == AMSI_RESULT_DETECTED {
            println!("[+] chunk {}", i + 1);
            println!("{}", "-".repeat(60));
            println!("{}", c.red());
            println!("{}\n", "-".repeat(60));
        }
    }
}
