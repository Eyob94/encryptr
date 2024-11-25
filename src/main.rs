use std::str::FromStr;

use clap::Parser;
use file_encryptr::{Algorithm, Cli, Config, Encryptr, Operation};
use rpassword::read_password;
use shush_rs::SecretString;

fn main() {
    tracing_subscriber::fmt::init();

    let mut cli = Cli::parse();

    if cli.operation.is_none() {
        cli.operation = Some(Operation::Encrypt); // Default to Encrypt
    }

    let config = Config {
        in_file: cli.in_path,
        out_file: cli.out,
        enc_algorithm: Algorithm::ChaChaPoly,
    };
    let password =
        SecretString::from_str(read_password_from_user().as_str()).expect("Error reading password");

    let mut encryptr = Encryptr::new(config, password).unwrap();

    match cli.operation {
        Some(Operation::Encrypt) => {
            encryptr
                .encrypt()
                .expect("Error encrypting file\n aborting...");
        }
        Some(Operation::Decrypt) => {
            encryptr
                .decrypt()
                .expect("Error encrypting file\n aborting...");
        }
        Some(Operation::ShowInfo) => {
            encryptr.show_info().unwrap();
        }
        None => unreachable!(),
    }
}

fn read_password_from_user() -> String {
    println!("Enter password: ");
    read_password().expect("Failed to read password")
}
