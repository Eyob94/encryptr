mod config;
mod encryption;
mod encryptr;
mod errors;
mod utils;
mod wal;
mod cli;

pub use config::*;
pub use encryptr::*;
pub use cli::*;
pub use encryption::*;

#[derive(Debug, Clone)]
pub struct Metadata {
    // Name of the file
    file_name: [u8; 256],
    // Size(in bytes) of the file
    file_size: u64,
}

impl Metadata {
    pub fn to_bytes(&self) -> [u8; 296] {
        let mut buffer = [0u8; 296];

        buffer[0..256].copy_from_slice(&self.file_name);

        buffer[256..264].copy_from_slice(&self.file_size.to_le_bytes());

        buffer
    }

    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> anyhow::Result<Self> {
        let bytes = bytes.as_ref();
        assert_eq!(bytes.len(), 296, "Expected byte slice of length 296");
        let mut file_name = [0u8; 256];
        file_name.copy_from_slice(&bytes[0..256]);

        let file_size = u64::from_le_bytes(bytes[256..264].try_into()?);

        let mut file_type = [0u8; 32];
        file_type.copy_from_slice(&bytes[264..296]);

        Ok(Metadata {
            file_name,
            file_size,
        })
    }
}
