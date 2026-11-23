//! The website's command table (`website/src/commands.json`) must agree
//! with the binary: a command is marked `supported` or `partial` exactly
//! when `baldssl help` lists it, and every such command is one OpenSSL has
//! (a standard command, or a digest shortcut such as `sha256`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{collections::BTreeSet, fs, path::Path, process::Command};

/// `(kind, name, status)` per command. The file is written one object per
/// line by `scripts/gen-commands.py`, which keeps this parser trivial.
/// The binary under test: the native build, or whatever `BALDSSL_BIN` names
/// (e.g. `scripts/wasmtime-baldssl.sh`, to run the WebAssembly build).
fn binary() -> std::ffi::OsString {
    std::env::var_os("BALDSSL_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_baldssl").into())
}

fn table() -> Vec<(String, String, String)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../website/src/commands.json");
    let field = |line: &str, key: &str| -> String {
        let start =
            line.find(&format!("\"{key}\": \"")).unwrap() + key.len() + 5;
        let end = start + line[start..].find('"').unwrap();
        line[start..end].to_string()
    };
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| l.trim_start().starts_with("{\"name\""))
        .map(|l| (field(l, "kind"), field(l, "name"), field(l, "status")))
        .collect()
}

fn dispatched() -> BTreeSet<String> {
    let out = Command::new(binary()).arg("help").output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next().map(String::from))
        .collect()
}

#[test]
fn website_status_matches_the_binary() {
    let table = table();
    assert!(table.len() > 100, "parsed {} commands", table.len());
    let implemented: BTreeSet<String> = table
        .iter()
        .filter(|(_, _, s)| s == "supported" || s == "partial")
        .map(|(k, n, _)| {
            assert!(
                k == "standard" || k == "digest",
                "{n}: {k} commands are not dispatched"
            );
            n.clone()
        })
        .collect();
    assert_eq!(implemented, dispatched());
    for (_, name, status) in &table {
        assert!(
            ["supported", "partial", "planned", "not-started"]
                .contains(&status.as_str()),
            "{name}: {status}"
        );
    }
}
