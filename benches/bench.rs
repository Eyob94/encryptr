use criterion::{criterion_group, criterion_main, Criterion};
use file_encryptr::encrypt_chunk;
use rayon::prelude::*;
use shush_rs::SecretVec;

// 100MB
const DATA_SIZE: usize = 100 * 1024 * 1024;

fn prepare_test_data() -> Vec<u8> {
    vec![0u8; DATA_SIZE]
}

/// Parallel encryption using 512KB chunks
fn encrypt_parallel(
    data: &[u8],
    key: &SecretVec<u8>,
    nonce: [u8; 12],
    chunk_size: usize,
) -> Vec<u8> {
    data.par_chunks(chunk_size)
        .flat_map(|chunk| encrypt_chunk(&chunk.to_vec(), key, nonce).unwrap_or_else(|_| vec![]))
        .collect()
}

/// Serial encryption using 512KB chunks
fn encrypt_serial(data: &[u8], key: &SecretVec<u8>, nonce: [u8; 12], chunk_size: usize) -> Vec<u8> {
    data.chunks(chunk_size)
        .flat_map(|chunk| encrypt_chunk(&chunk.to_vec(), key, nonce).unwrap_or_else(|_| vec![]))
        .collect()
}

fn benchmark_encryption(c: &mut Criterion) {
    let key = SecretVec::from(vec![0u8; 32]);
    let nonce = [0u8; 12];
    let data = prepare_test_data();

    c.bench_function("parallel encryption (256KB chunks)", |b| {
        b.iter(|| encrypt_parallel(&data, &key, nonce, 256 * 1024));
    });

    c.bench_function("serial encryption (256KB chunks)", |b| {
        b.iter(|| encrypt_serial(&data, &key, nonce, 256 * 1024));
    });

    c.bench_function("parallel encryption (512KB chunks)", |b| {
        b.iter(|| encrypt_parallel(&data, &key, nonce, 512 * 1024));
    });

    c.bench_function("serial encryption (512KB chunks)", |b| {
        b.iter(|| encrypt_serial(&data, &key, nonce, 512 * 1024));
    });
}

criterion_group!(benches, benchmark_encryption);
criterion_main!(benches);
