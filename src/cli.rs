use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    author = "Eyob",
    name = "file-encr",
    version = "0.1.0",
    about = "File encryptor"
)]
pub struct Cli {
    #[arg(short, long, help = "Input file path")]
    pub in_path: String,

    #[arg(short, long, help = "Output file path (optional)")]
    pub out: Option<String>,

    #[command(subcommand)]
    pub operation: Option<Operation>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Operation {
    Encrypt,
    Decrypt,
    ShowInfo
}
