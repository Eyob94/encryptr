use std::{
    fs,
    io::{BufWriter, Write},
    path::Path,
};

use anyhow::bail;
use chacha20poly1305::aead::Buffer;
use okaywal::{Entry, LogManager, Recovery, WriteAheadLog};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WALEntry {
    pub chunk_index: usize,
    pub encrypted_data: Vec<u8>,
    pub nonce: [u8; 12],
}

impl WALEntry {
    pub fn to_vec(&self) -> anyhow::Result<Vec<u8>> {
        let encoded: Vec<u8> = bincode::serialize(self)?;

        Ok(encoded)
    }

    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> anyhow::Result<Self> {
        let bytes = bytes.as_ref();
        let decoded: Self = bincode::deserialize(bytes)?;

        Ok(decoded)
    }

    fn get_length(&self) -> anyhow::Result<u32> {
        Ok(self.to_vec()?.len() as u32)
    }

    pub fn write_to_file<W: std::io::Write>(&self, file: &mut W) -> anyhow::Result<()> {
        let mut bufwriter = BufWriter::new(file);

        let length = self.get_length()?;

        bufwriter.write_all(&length.to_le_bytes())?;
        bufwriter.write_all(self.to_vec()?.as_slice())?;

        bufwriter.flush()?;

        Ok(())
    }
}

pub fn get_and_validate_wal_files<P: AsRef<Path>>(dir: P) -> anyhow::Result<Vec<String>> {
    let dir = dir.as_ref();
    let mut wal_files = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(file_name) = path.file_name() {
                if let Some(file_name_str) = file_name.to_str() {
                    if file_name_str.ends_with("_wal") {
                        wal_files.push(file_name_str.to_string());
                    }
                }
            }
        }
    }

    // Sort files by their numeric prefix
    wal_files.sort_by(|a, b| {
        let a_num = a
            .split('_')
            .next()
            .and_then(|n| n.parse::<u32>().ok())
            .unwrap_or(0);
        let b_num = b
            .split('_')
            .next()
            .and_then(|n| n.parse::<u32>().ok())
            .unwrap_or(0);
        a_num.cmp(&b_num)
    });

    // Validate sequence
    for (i, file_name) in wal_files.iter().enumerate() {
        let expected_number = (i + 1) as u32;
        let file_number = file_name
            .split('_')
            .next()
            .and_then(|n| n.parse::<u32>().ok())
            .unwrap_or(0);

        if file_number != expected_number {
            bail!("Missing or out of order WALs")
        }
    }

    // Add full paths to validated files
    let full_paths = wal_files
        .into_iter()
        .map(|file_name| dir.join(file_name).to_string_lossy().to_string())
        .collect();

    Ok(full_paths)
}
