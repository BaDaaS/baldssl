//! `baldssl`: a reimplementation of the `openssl` command-line tool.
//!
//! The first goal is compatibility: the same arguments, the same output
//! bytes. The OpenSSL-compatible commands are a thin layer over the library
//! crates, which hold the primitives.
//!
//! Exit codes: 0 on success, 1 on any error, 2 when an input file is missing.

mod args;
mod x509;

use std::{
    ffi::OsString,
    fmt::Write as _,
    fs,
    io::{self, Write},
    process::ExitCode,
};

use baldssl_core::Error;

const COMMANDS: &[(&str, &str)] = &[
    ("help", "List the commands"),
    ("version", "Print the baldssl version"),
    ("x509", "Display X.509 certificates"),
];

fn help() -> Vec<u8> {
    let mut s = String::from("Commands:\n");
    for (name, what) in COMMANDS {
        let _ = writeln!(s, "  {name:<10} {what}");
    }
    s.into_bytes()
}

/// Runs one command and returns the bytes to write and where.
fn dispatch(args: &[OsString]) -> Result<(Vec<u8>, Option<OsString>), Error> {
    let Some((command, rest)) = args.split_first() else {
        return Ok((help(), None));
    };
    match command.to_str() {
        Some("x509") => x509::render(rest),
        Some("version") => Ok((
            format!("baldssl {}\n", env!("CARGO_PKG_VERSION")).into_bytes(),
            None,
        )),
        Some("help" | "-help" | "--help") => Ok((help(), None)),
        _ => Err(Error::Usage(format!(
            "Invalid command '{}'; type \"help\" for a list.",
            command.to_string_lossy()
        ))),
    }
}

fn write_output(bytes: &[u8], path: Option<&OsString>) -> Result<(), Error> {
    let io_err = |context: String| {
        move |e: io::Error| Error::Io {
            context,
            message: e.to_string(),
        }
    };
    if let Some(p) = path {
        fs::write(p, bytes)
            .map_err(io_err(format!("writing {}", p.to_string_lossy())))
    } else {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(bytes)
            .and_then(|()| stdout.flush())
            .map_err(io_err("writing stdout".into()))
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = dispatch(&args)
        .and_then(|(out, path)| write_output(&out, path.as_ref()));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let command = args
                .first()
                .map_or_else(|| "baldssl".into(), |c| c.to_string_lossy());
            eprintln!("{command}: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
