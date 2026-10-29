//! The Rust GPT writer (`gpt::raw_image`, used by `urmqtt-disk create` and
//! the self-installing ISO) must produce exactly the bytes of
//! `scripts/mkraw.py`, the tool that builds the release raw images (M17).
//! Skipped if `python3` is missing.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn raw_image_equals_mkraw_py() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = std::env::temp_dir().join(format!("urmqtt-gpt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for sectors in [1usize, 2047, 2048, 2049, 6000] {
        let esp: Vec<u8> = (0..sectors * 512).map(|i| (i * 13 % 253) as u8).collect();
        let (esp_path, out) = (dir.join("esp.img"), dir.join("out.img"));
        std::fs::write(&esp_path, &esp).unwrap();
        let Ok(st) = Command::new("python3")
            .arg("-I")
            .arg(root.join("scripts/mkraw.py"))
            .arg(&esp_path)
            .arg(&out)
            .output()
        else {
            eprintln!("python3 not found: skipped");
            return;
        };
        assert!(
            st.status.success(),
            "{}",
            String::from_utf8_lossy(&st.stderr)
        );
        let py = std::fs::read(&out).unwrap();
        let rs = urmqtt_store::gpt::raw_image(&esp).unwrap();
        assert_eq!(py.len(), rs.len(), "{sectors} sectors: length");
        if let Some(i) = py.iter().zip(&rs).position(|(a, b)| a != b) {
            panic!("{sectors} sectors: first difference at byte {i}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
