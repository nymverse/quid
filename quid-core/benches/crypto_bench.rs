//! Cryptographic operation benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use quid_core::{QuIDIdentity, SecurityLevel};

fn benchmark_key_generation(c: &mut Criterion) {
    c.bench_function("key_generation_level1", |b| {
        b.iter(|| {
            let (identity, _keypair) = QuIDIdentity::new(black_box(SecurityLevel::Level1)).unwrap();
            black_box(identity);
        })
    });
    
    c.bench_function("key_generation_level3", |b| {
        b.iter(|| {
            let (identity, _keypair) = QuIDIdentity::new(black_box(SecurityLevel::Level3)).unwrap();
            black_box(identity);
        })
    });
}

fn benchmark_signing(c: &mut Criterion) {
    let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
    let message = b"benchmark message for signing";
    
    c.bench_function("sign_message", |b| {
        b.iter(|| {
            let signature = keypair.sign(black_box(message)).unwrap();
            black_box(signature);
        })
    });
}

fn benchmark_verification(c: &mut Criterion) {
    let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
    let message = b"benchmark message for verification";
    let signature = keypair.sign(message).unwrap();
    
    c.bench_function("verify_signature", |b| {
        b.iter(|| {
            let result = keypair.verify(black_box(message), black_box(&signature)).unwrap();
            black_box(result);
        })
    });
}

criterion_group!(benches, benchmark_key_generation, benchmark_signing, benchmark_verification);
criterion_main!(benches);
