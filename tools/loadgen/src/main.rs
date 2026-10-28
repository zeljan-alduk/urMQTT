//! Host-side load generator (section 10 of PROMPT.md).
//!
//! **Status: not implemented.** It needs the TLS listener (M10) to have a
//! target; until then it exits with an explicit error instead of pretending.

fn main() {
    eprintln!("urmqtt-loadgen: not implemented yet (planned for M10/M13, see docs/PROGRESS.md)");
    std::process::exit(2);
}
