//! `cargo run --release -p urmqtt-tls --example profile`: where the time of a
//! TLS 1.3 + mTLS handshake goes on this machine (X9).

fn now() -> u64 {
    static T0: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    u64::try_from(T0.get_or_init(std::time::Instant::now).elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn main() {
    let p = urmqtt_tls::bench::run(now);
    println!("{p}");
    println!(
        "public-key {} us, symmetric {} us, handshake {} us",
        p.public_key_ns() / 1000,
        p.symmetric_ns() / 1000,
        p.handshake_ns() / 1000
    );
}
