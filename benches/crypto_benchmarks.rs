use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use qasa::{
    aes,
    dilithium::{self, DilithiumKeyPair, DilithiumVariant},
    kyber::{KyberKeyPair, KyberVariant},
    utils,
};

fn kyber_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("kyber");

    // Benchmark Kyber key generation
    for variant in [
        KyberVariant::Kyber512,
        KyberVariant::Kyber768,
        KyberVariant::Kyber1024,
    ]
    .iter()
    {
        group.bench_with_input(
            BenchmarkId::new("key_generation", variant.to_string()),
            variant,
            |b, &variant| b.iter(|| KyberKeyPair::generate(variant)),
        );
    }

    // Benchmark Kyber encapsulation
    for variant in [
        KyberVariant::Kyber512,
        KyberVariant::Kyber768,
        KyberVariant::Kyber1024,
    ]
    .iter()
    {
        let key_pair = KyberKeyPair::generate(*variant).unwrap();
        group.bench_with_input(
            BenchmarkId::new("encapsulation", variant.to_string()),
            variant,
            |b, _| b.iter(|| key_pair.encapsulate()),
        );
    }

    // Benchmark Kyber decapsulation
    for variant in [
        KyberVariant::Kyber512,
        KyberVariant::Kyber768,
        KyberVariant::Kyber1024,
    ]
    .iter()
    {
        let key_pair = KyberKeyPair::generate(*variant).unwrap();
        let (ciphertext, _) = key_pair.encapsulate().unwrap();

        group.bench_with_input(
            BenchmarkId::new("decapsulation", variant.to_string()),
            variant,
            |b, _| b.iter(|| key_pair.decapsulate(&ciphertext)),
        );
    }

    group.finish();
}

fn dilithium_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("dilithium");

    // Benchmark Dilithium key generation
    for variant in [
        DilithiumVariant::Dilithium2,
        DilithiumVariant::Dilithium3,
        DilithiumVariant::Dilithium5,
    ]
    .iter()
    {
        group.bench_with_input(
            BenchmarkId::new("key_generation", variant.to_string()),
            variant,
            |b, &variant| b.iter(|| DilithiumKeyPair::generate(variant)),
        );
    }

    // Test message for signing
    let message = b"This is a test message for benchmarking signature operations";

    // Benchmark Dilithium signing
    for variant in [
        DilithiumVariant::Dilithium2,
        DilithiumVariant::Dilithium3,
        DilithiumVariant::Dilithium5,
    ]
    .iter()
    {
        let key_pair = DilithiumKeyPair::generate(*variant).unwrap();

        group.bench_with_input(
            BenchmarkId::new("sign", variant.to_string()),
            variant,
            |b, _| b.iter(|| key_pair.sign(message)),
        );
    }

    // Benchmark Dilithium verification
    for variant in [
        DilithiumVariant::Dilithium2,
        DilithiumVariant::Dilithium3,
        DilithiumVariant::Dilithium5,
    ]
    .iter()
    {
        let key_pair = DilithiumKeyPair::generate(*variant).unwrap();
        let signature = key_pair.sign(message).unwrap();

        group.bench_with_input(
            BenchmarkId::new("verify", variant.to_string()),
            variant,
            |b, _| b.iter(|| key_pair.verify(message, &signature)),
        );
    }

    // Benchmark public key verification (more common use case)
    for variant in [
        DilithiumVariant::Dilithium2,
        DilithiumVariant::Dilithium3,
        DilithiumVariant::Dilithium5,
    ]
    .iter()
    {
        let key_pair = DilithiumKeyPair::generate(*variant).unwrap();
        let pub_key = key_pair.public_key();
        let signature = key_pair.sign(message).unwrap();

        group.bench_with_input(
            BenchmarkId::new("pub_key_verify", variant.to_string()),
            variant,
            |b, _| b.iter(|| pub_key.verify(message, &signature)),
        );
    }

    group.finish();
}

fn dilithium_optimized_benchmarks(c: &mut Criterion) {
    // Test message for signing
    let message = b"This is a test message for benchmarking optimized signature operations";
    let mut group = c.benchmark_group("dilithium_optimized");

    for variant in [
        DilithiumVariant::Dilithium2,
        DilithiumVariant::Dilithium3,
        DilithiumVariant::Dilithium5,
    ]
    .iter()
    {
        // Generate a key pair for testing
        let key_pair = DilithiumKeyPair::generate(*variant).unwrap();

        // Benchmark regular signing
        group.bench_with_input(
            BenchmarkId::new("standard_sign", variant.to_string()),
            variant,
            |b, _| b.iter(|| key_pair.sign(message)),
        );

        // Benchmark lean signing
        group.bench_with_input(
            BenchmarkId::new("lean_sign", variant.to_string()),
            variant,
            |b, _| b.iter(|| dilithium::lean_sign(message, &key_pair.secret_key, *variant)),
        );

        // Generate a signature for verification benchmarks
        let signature = key_pair.sign(message).unwrap();

        // Benchmark regular verification
        group.bench_with_input(
            BenchmarkId::new("standard_verify", variant.to_string()),
            variant,
            |b, _| b.iter(|| key_pair.verify(message, &signature)),
        );

        // Benchmark lean verification
        group.bench_with_input(
            BenchmarkId::new("lean_verify", variant.to_string()),
            variant,
            |b, _| {
                b.iter(|| {
                    dilithium::lean_verify(message, &signature, &key_pair.public_key, *variant)
                })
            },
        );

        // Benchmark batch verification (3 signatures)
        let batch = vec![
            (
                message as &[u8],
                signature.as_ref(),
                key_pair.public_key.as_ref(),
                *variant,
            ),
            (
                message as &[u8],
                signature.as_ref(),
                key_pair.public_key.as_ref(),
                *variant,
            ),
            (
                message as &[u8],
                signature.as_ref(),
                key_pair.public_key.as_ref(),
                *variant,
            ),
        ];

        group.bench_with_input(
            BenchmarkId::new("batch_verify", variant.to_string()),
            variant,
            |b, _| b.iter(|| dilithium::lean_verify_batch(&batch)),
        );
    }

    group.finish();
}

fn aes_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes-gcm");

    // Generate a key and some test data
    let key = utils::random_bytes(32).unwrap();
    let small_data = b"This is a small message for testing";
    let medium_data = vec![0; 1000]; // 1KB
    let large_data = vec![0; 1_000_000]; // 1MB

    // Benchmark encryption with different data sizes
    group.bench_function("encrypt_small", |b| {
        b.iter(|| aes::encrypt(small_data, &key, Some(b"")))
    });

    group.bench_function("encrypt_medium", |b| {
        b.iter(|| aes::encrypt(&medium_data, &key, Some(b"")))
    });

    group.bench_function("encrypt_large", |b| {
        b.iter(|| aes::encrypt(&large_data, &key, Some(b"")))
    });

    // Benchmark decryption with different data sizes
    let (small_encrypted, small_nonce) = aes::encrypt(small_data, &key, Some(b"")).unwrap();
    let (medium_encrypted, medium_nonce) = aes::encrypt(&medium_data, &key, Some(b"")).unwrap();
    let (large_encrypted, large_nonce) = aes::encrypt(&large_data, &key, Some(b"")).unwrap();

    group.bench_function("decrypt_small", |b| {
        b.iter(|| aes::decrypt(&small_encrypted, &key, &small_nonce, Some(b"")))
    });

    group.bench_function("decrypt_medium", |b| {
        b.iter(|| aes::decrypt(&medium_encrypted, &key, &medium_nonce, Some(b"")))
    });

    group.bench_function("decrypt_large", |b| {
        b.iter(|| aes::decrypt(&large_encrypted, &key, &large_nonce, Some(b"")))
    });

    // Benchmark streaming encryption/decryption
    group.bench_function("stream_encrypt_large", |b| {
        b.iter(|| {
            use std::io::Cursor;
            let cipher = aes::AesGcm::new(&key).unwrap();
            let nonce = aes::AesGcm::generate_nonce();
            let mut input = Cursor::new(&large_data);
            let mut output = Vec::new();
            cipher.encrypt_stream(&mut input, &mut output, &nonce, Some(b""), None)
        })
    });

    group.bench_function("stream_decrypt_large", |b| {
        b.iter_with_setup(
            || {
                // Setup: encrypt data with streaming
                use std::io::Cursor;
                let cipher = aes::AesGcm::new(&key).unwrap();
                let nonce = aes::AesGcm::generate_nonce();
                let mut input = Cursor::new(&large_data);
                let mut encrypted = Vec::new();
                cipher.encrypt_stream(&mut input, &mut encrypted, &nonce, Some(b""), None).unwrap();
                (cipher, nonce, encrypted)
            },
            |(cipher, nonce, encrypted)| {
                // Benchmark: decrypt the data
                use std::io::Cursor;
                let mut input = Cursor::new(&encrypted);
                let mut output = Vec::new();
                cipher.decrypt_stream(&mut input, &mut output, &nonce, Some(b""))
            },
        )
    });

    // Benchmark with different chunk sizes
    for &chunk_size_kb in &[64, 256, 1024] {
        let chunk_size = chunk_size_kb * 1024;
        let chunk_name = format!("{}KB", chunk_size_kb);
        
        group.bench_with_input(
            BenchmarkId::new("stream_encrypt_chunk", &chunk_name),
            &chunk_size,
            |b, &chunk_size| {
                b.iter(|| {
                    use std::io::Cursor;
                    let cipher = aes::AesGcm::new(&key).unwrap();
                    let nonce = aes::AesGcm::generate_nonce();
                    let mut input = Cursor::new(&large_data);
                    let mut output = Vec::new();
                    cipher.encrypt_stream(&mut input, &mut output, &nonce, Some(b""), Some(chunk_size))
                })
            },
        );
    }

    group.finish();
}

fn utils_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("utils");

    // Benchmark random_bytes
    for size in [32, 1000, 10000].iter() {
        group.bench_with_input(BenchmarkId::new("random_bytes", size), size, |b, &size| {
            b.iter(|| utils::random_bytes(size))
        });
    }

    // Benchmark constant time comparison
    let data1 = utils::random_bytes(1000).unwrap();
    let data2 = data1.clone();

    group.bench_function("constant_time_eq", |b| {
        b.iter(|| utils::constant_time_eq(&data1, &data2))
    });

    // Benchmark secure_zero
    group.bench_function("secure_zero", |b| {
        b.iter(|| {
            let mut data = vec![0xFF; 1000];
            utils::secure_zero(&mut data);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    kyber_benchmarks,
    dilithium_benchmarks,
    dilithium_optimized_benchmarks,
    aes_benchmarks,
    utils_benchmarks
);
criterion_main!(benches);
