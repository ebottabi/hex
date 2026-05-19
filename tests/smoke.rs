use std::process::Command;

#[test]
fn boots_in_default_mode() {
    let bin = env!("CARGO_BIN_EXE_hex");
    let output = Command::new(bin)
        .output()
        .expect("failed to run hex binary");

    assert!(
        output.status.success(),
        "hex exited with non-zero status: {:?}",
        output.status.code()
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hex bootstrap"),
        "unexpected stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("mode: interactive"),
        "unexpected stdout: {}",
        stdout
    );
}
