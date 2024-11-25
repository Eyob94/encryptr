use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("File Error: {0}")]
    FileError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
