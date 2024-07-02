use clap::Parser;

#[derive(Debug, Parser)]
#[clap(
    name = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS"),
    about = env!("CARGO_PKG_DESCRIPTION"),
    arg_required_else_help = true,
    group(
        clap::ArgGroup::new("source")
            .required(true)
            .args(&["filename", "command", "stdin"]),
    ),
)]
pub struct Command {
    // act1 = entire script
    // act2 = scan per chunk
    // act3 = scan per line
    // act4 =
    #[clap(long = "act", value_name = "ACT", default_value_t = 1)]
    pub act: u8,
    #[clap(short = 'f', long = "filename", value_name = "FILENAME")]
    pub filename: Option<String>,
    #[clap(short = 'c', long = "command", value_name = "COMMAND")]
    pub command: Option<String>,
    #[clap(short = 's', long = "stdin")]
    pub stdin: bool,
    #[clap( long = "chunksize", value_name = "CHUNKSIZE", default_value_t = 2048)]
    pub chunk_size: usize
}
