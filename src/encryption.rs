use anyhow::anyhow;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use shush_rs::{ExposeSecret, SecretVec};
use tracing::error;

pub fn encrypt_chunk(
    chunk: &Vec<u8>,
    key: &SecretVec<u8>,
    rand_nonce_key: [u8; 12],
) -> anyhow::Result<Vec<u8>> {
    let secret = key.expose_secret();

    let cipher_key = Key::from_slice(secret.as_slice());

    let cipher = ChaCha20Poly1305::new(cipher_key);

    let nonce = Nonce::from_slice(&rand_nonce_key);

    let encrypted_chunk = cipher
        .encrypt(nonce, chunk.as_slice())
        .map_err(|_| anyhow!("Error encrypting data"))?;
    Ok(encrypted_chunk)
}

pub(crate) fn decrypt_chunk(
    encrypted_chunk: Vec<u8>,
    key: &SecretVec<u8>,
    rand_nonce_key: [u8; 12],
) -> anyhow::Result<Vec<u8>> {
    let secret = key.expose_secret();

    let cipher_key = Key::from_slice(secret.as_slice());

    let cipher = ChaCha20Poly1305::new(cipher_key);

    let nonce = Nonce::from_slice(&rand_nonce_key);

    let decrypted_chunk = cipher
        .decrypt(nonce, encrypted_chunk.as_slice())
        .map_err(|e| {
            error!("Error {}", e);
            anyhow!("Error decrypting data")
        })?;
    Ok(decrypted_chunk)
}

#[cfg(test)]
mod test {
    use shush_rs::SecretVec;

    use crate::encryption::{decrypt_chunk, encrypt_chunk};

    #[test]
    fn test_encrypt_decrypt_round_trip() -> anyhow::Result<()> {
        let key = SecretVec::from(vec![0u8; 32]);
        let nonce = [0u8; 12];
        let chunk = b"Test data to encrypt".to_vec();

        let encrypted = encrypt_chunk(&chunk, &key, nonce)?;
        let decrypted = decrypt_chunk(encrypted, &key, nonce)?;

        assert_eq!(chunk, decrypted, "Decrypted data does not match original");
        println!("Encryption and decryption successful!");
        Ok(())
    }
}
