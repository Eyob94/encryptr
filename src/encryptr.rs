use std::{
    fs::{remove_file, File},
    io::{Read, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
};

use anyhow::{anyhow, bail};
use iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use rayon::*;
use shush_rs::{ExposeSecret, SecretString, SecretVec};
use tracing::info;

use crate::{
    encryption::{decrypt_chunk, encrypt_chunk},
    utils::{bytes_to_human_readable, filter_zero_bytes, slice_to_array},
    wal::{get_and_validate_wal_files, WALEntry},
    Config, Metadata,
};

#[derive(Debug)]
pub struct Encryptr {
    key: SecretVec<u8>,
    config: Config,
    metadata: Metadata,
    file_chunks: Vec<Vec<u8>>,
}

impl Encryptr {
    pub fn new(config: Config, password: SecretString) -> anyhow::Result<Self> {
        let (metadata, chunks) = Encryptr::load_file(&config.in_file)?;

        let password = password.expose_secret();

        let key = blake3::hash(password.as_bytes()).as_bytes().to_vec();

        Ok(Self {
            key: SecretVec::from(key),
            config,
            metadata,
            file_chunks: chunks,
        })
    }
    fn load_file<T: AsRef<str>>(path: T) -> anyhow::Result<(Metadata, Vec<Vec<u8>>)> {
        let path = path.as_ref();
        let file_name = Path::new(path)
            .file_name()
            .ok_or_else(|| anyhow!("Error getting file name"))?;

        if file_name.as_bytes().len() > 256 {
            bail!("File name too long")
        }

        let file_name_in_bytes: [u8; 256] = slice_to_array(file_name.as_bytes())?;

        let mut file = File::options().read(true).open(path)?;

        let file_size = file.metadata().unwrap().size();

        let chunk_size = (file_size as f64 / 512.0 * 1024.0).ceil() as usize;

        let mut chunks: Vec<Vec<u8>> = Vec::with_capacity(chunk_size);

        // 512kb buffer
        let mut buffer = [0u8; 512 * 1024];

        loop {
            let bytes_read = file.read(&mut buffer)?;

            if bytes_read == 0 {
                break; // EOF reached
            }

            chunks.push(buffer[..bytes_read].to_vec());
        }

        info!("Read {file_size} bytes in {} chunks", chunk_size);

        let file_metadata = Metadata {
            file_name: file_name_in_bytes,
            file_size,
        };

        Ok((file_metadata, chunks))
    }

    pub fn encrypt(&mut self) -> anyhow::Result<String> {
        self.file_chunks
            .par_iter_mut()
            .enumerate()
            .for_each(|(index, chunk)| {
                let rand_nonce_key = rand::random::<[u8; 12]>();
                let encrypted_chunk = encrypt_chunk(chunk, &self.key, rand_nonce_key).unwrap();
                let wal_entry = WALEntry {
                    chunk_index: index,
                    encrypted_data: encrypted_chunk.clone(),
                    nonce: rand_nonce_key,
                };

                // 0 is for metadata
                let mut file = File::create(format!("/tmp/{}_wal", index + 1)).unwrap();

                wal_entry.write_to_file(&mut file).unwrap();
            });

        self.combine()
    }

    fn combine(&self) -> anyhow::Result<String> {
        let rand_nonce_key = rand::random::<[u8; 12]>();

        let encrypted_metadata = encrypt_chunk(
            &self.metadata.to_bytes().to_vec(),
            &self.key,
            rand_nonce_key,
        )?;

        let file_name = match self.config.out_file {
            Some(ref name) => name.clone(),

            None => hex::encode(blake3::hash(&self.metadata.file_name).as_bytes()),
        };

        let mut new_file = File::create(&file_name)?;

        let wal_entry = WALEntry {
            chunk_index: 0,
            encrypted_data: encrypted_metadata,
            nonce: rand_nonce_key,
        };
        wal_entry.write_to_file(&mut new_file)?;

        let files = get_and_validate_wal_files("/tmp")?;

        for f in files.iter() {
            let mut file = File::options().read(true).open(f)?;
            let mut buffer = vec![0u8; file.metadata()?.size() as usize];
            file.read_exact(&mut buffer)?;

            new_file.write_all(buffer.as_slice())?;
            remove_file(f)?;
        }

        info!("File Successfully encrypted at {}", file_name);

        Ok(file_name)
    }

    pub fn decrypt(&self) -> anyhow::Result<()> {
        let mut file = File::options().read(true).open(&self.config.in_file)?;

        let metadata = Self::decrypt_metadata(&mut file, &self.key)?;

        let file_name = String::from_utf8(filter_zero_bytes(&metadata.file_name))?;

        let mut new_file = File::create(file_name.clone())?;

        loop {
            let mut length_buffer = [0u8; 4];
            if file.read_exact(&mut length_buffer).is_err() {
                break; // EOF reached
            }

            let entry_length = u32::from_le_bytes(length_buffer);
            let mut entry_buffer = vec![0u8; entry_length as usize];
            file.read_exact(&mut entry_buffer)?;

            // Deserialize the WAL entry
            let wal_entry = WALEntry::from_bytes(entry_buffer)?;

            // Decrypt the chunk using the nonce
            let decrypted_chunk =
                decrypt_chunk(wal_entry.encrypted_data, &self.key, wal_entry.nonce)?;

            // Write the decrypted chunk to the output file
            new_file.write_all(&decrypted_chunk)?;
        }

        info!("File successfully decrypted: {file_name}");

        Ok(())
    }

    pub fn show_info(&self) -> anyhow::Result<Metadata> {
        let mut file = File::options().read(true).open(&self.config.in_file)?;

        let metadata = Self::decrypt_metadata(&mut file, &self.key)?;
        let file_name = String::from_utf8(filter_zero_bytes(&metadata.file_name))?;
        let file_size = metadata.file_size;

        info!(
            r"
            File_Name: {} 
            File Size: {}
            Encryption Algorithm: ChaCha20Poly1305
        ",
            file_name,
            bytes_to_human_readable(file_size)
        );

        Ok(metadata)
    }

    fn decrypt_metadata(file: &mut File, key: &SecretVec<u8>) -> anyhow::Result<Metadata> {
        let mut length_buffer = [0u8; 4];
        file.read_exact(&mut length_buffer)?;

        // Convert the length buffer to a u32
        let data_length = u32::from_le_bytes(length_buffer);
        info!("data length is {data_length}");

        let mut data_buffer = vec![0u8; data_length as usize];
        file.read_exact(&mut data_buffer)?;

        let wal_entry = WALEntry::from_bytes(data_buffer)?;

        let decrypted_metadata = decrypt_chunk(wal_entry.encrypted_data, key, wal_entry.nonce)?;
        let metadata = Metadata::from_bytes(decrypted_metadata)?;

        Ok(metadata)
    }
}

#[cfg(test)]
mod test {

    use std::{env::temp_dir, io::Write, str::FromStr, time::Instant};

    use crate::Algorithm;

    use super::*;

    #[test]
    fn loads_file() {
        let tempdir = temp_dir();
        let temp_file = format!("{}/temp_file.txt", tempdir.to_str().unwrap());

        // Create a large file (100 MB for testing)
        let mut file = File::create(&temp_file).unwrap();
        for _ in 0..10_000_000 {
            file.write_all(b"The quick brown fox jumps over the lazy dog")
                .unwrap();
        }
        file.write_all(b"This is the last sentence in there")
            .unwrap();
        file.flush().unwrap();

        let config = Config {
            in_file: temp_file.to_string(),
            out_file: None,
            enc_algorithm: Algorithm::ChaChaPoly,
        };

        let mut encryptr = Encryptr::new(config, SecretString::from_str("sample_password").unwrap()).unwrap();
        let start = Instant::now();

        println!("Encryption started");
        let file_name = encryptr.encrypt().unwrap();

        println!("Took {:?}", start.elapsed());

        let config = Config {
            in_file: file_name.to_string(),
            out_file: None,
            enc_algorithm: Algorithm::ChaChaPoly,
        };

        let encryptr = Encryptr::new(config, SecretString::from_str("sample_password").unwrap()).unwrap();

        encryptr.decrypt().unwrap()
    }
}
