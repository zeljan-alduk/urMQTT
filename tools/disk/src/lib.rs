//! Library of the `urmqtt-disk` host tool (STORAGE-PLAN S1, S2, S3): the
//! devices it works on, the host-side SQLite and telemetry checks, and the
//! offline migration. The command line is `main.rs`.

pub mod dev;
pub mod host;
pub mod migrate;
