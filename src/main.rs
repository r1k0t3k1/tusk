use core::panic;

use std::fs::File;
use std::io::{self, Read};

use clap::Parser;

mod command;
mod scanner;
mod processor;

fn main() {
    let cli = command::Command::parse();

    if cli.act < 1 || cli.act > 4 {
        eprintln!("\"act\" must be greater than or equal to 1 and less than or equal to 4.");
        return;
    } 

    let script: String = if cli.filename.is_some() {
        let mut f = File::open(cli.filename.unwrap()).expect("file not found.");
        let mut buf = String::new();
        f.read_to_string(&mut buf).expect("something went wrong reading the file.");
        buf
    } else if cli.command.is_some() {
        cli.command.unwrap()
    } else if cli.stdin {
        io::stdin().lines().fold("".to_string(), |acc, line| {
            acc + &line.unwrap() + "\n"
        })
    } else {
        panic!("something went wrong.");
    };

    let scanner = scanner::Scanner::new();

    match cli.act {
        1 => processor::process_entire_script(&scanner, &script),
        2 => processor::process_script_per_chunk(&scanner, &script, 15),
        3 => processor::process_script_per_line(&scanner, &script),
        4 => processor::process(&scanner, &script, cli.chunk_size),
        _ => (),
    }

}
