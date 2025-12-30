use rcypher::{Argon2Params, CypherVersion, EncryptionKey};
use std::time::Instant;

fn benchmark_key_derivation(params: &Argon2Params, iterations: u32) -> std::time::Duration {
    let password = "test_password_for_benchmarking";
    let version = CypherVersion::V7WithKdf;

    let start = Instant::now();
    for _ in 0..iterations {
        let _key = EncryptionKey::from_password_with_params(version.clone(), password, params)
            .expect("Key derivation failed");
    }
    start.elapsed()
}

fn main() {
    let iterations = 10;

    println!(
        "Benchmarking Argon2 key derivation ({} iterations each)...\n",
        iterations
    );

    // Benchmark with default (secure) parameters
    println!("Testing SECURE parameters (default):");
    println!("  Memory: {} KiB", Argon2Params::default().memory_cost);
    println!("  Time cost: {}", Argon2Params::default().time_cost);
    println!("  Parallelism: {}", Argon2Params::default().parallelism);

    let secure_duration = benchmark_key_derivation(&Argon2Params::default(), iterations);
    let secure_per_iter = secure_duration / iterations;

    println!("  Total time: {:.2?}", secure_duration);
    println!("  Per iteration: {:.2?}\n", secure_per_iter);

    // Benchmark with insecure (fast) parameters
    println!("Testing INSECURE parameters (for testing):");
    println!("  Memory: {} KiB", Argon2Params::insecure().memory_cost);
    println!("  Time cost: {}", Argon2Params::insecure().time_cost);
    println!("  Parallelism: {}", Argon2Params::insecure().parallelism);

    let insecure_duration = benchmark_key_derivation(&Argon2Params::insecure(), iterations);
    let insecure_per_iter = insecure_duration / iterations;

    println!("  Total time: {:.2?}", insecure_duration);
    println!("  Per iteration: {:.2?}\n", insecure_per_iter);

    // Calculate speedup
    let speedup = secure_duration.as_secs_f64() / insecure_duration.as_secs_f64();
    println!("Speedup: {:.1}x faster with insecure parameters", speedup);
    println!(
        "Time saved per derivation: {:.2?}",
        secure_per_iter - insecure_per_iter
    );
}
