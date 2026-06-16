//! Generates the Rorschach shared secrets used to authenticate to KrakenWAF's
//! rule-management API (`RORSCHACH_SECRET_EVEN` / `RORSCHACH_SECRET_ODD`).
//!
//! When KrakenWAF and kraken-ui share a container they should share one
//! `/run/secrets/krakenwaf/<NAME>` mount and there is nothing to generate here.
//! Use this tool for a *split* deployment, where the two services run in
//! different containers and each needs its own copy of the same secret pair:
//! generate once, then install the identical values on both sides.
//!
//! Usage:
//!   rorschach_keygen              Print `NAME=value` lines to stdout.
//!   rorschach_keygen --write      Write CIS-style secret files under
//!                                 /run/secrets/krakenwaf (dir 0750, files 0440).
//!   rorschach_keygen --dir PATH   Write the files under PATH instead.
//!
//! Secrets are 64 random bytes, base64url-encoded without padding — exactly the
//! format KrakenWAF documents. They are written only to stdout or the requested
//! files, never to logs.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// CIS-benchmark recommended location for container secrets, shared with
/// KrakenWAF's file-first resolution.
const DEFAULT_SECRETS_DIR: &str = "/run/secrets/krakenwaf";
const SECRET_NAMES: [&str; 2] = ["RORSCHACH_SECRET_EVEN", "RORSCHACH_SECRET_ODD"];
const SECRET_BYTES: usize = 64;

fn main() -> ExitCode {
    let mut destination: Option<PathBuf> = None;
    // Plain CLI flag parsing; argv drives no security decision.
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--write" => destination = Some(PathBuf::from(DEFAULT_SECRETS_DIR)),
            "--dir" => match args.next() {
                Some(path) => destination = Some(PathBuf::from(path)),
                None => {
                    eprintln!("--dir requires a path argument");
                    return ExitCode::FAILURE;
                }
            },
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_help();
                return ExitCode::FAILURE;
            }
        }
    }

    let secrets: Vec<(&str, String)> = SECRET_NAMES
        .iter()
        .map(|name| (*name, generate_secret()))
        .collect();

    match destination {
        Some(directory) => match write_secret_files(&directory, &secrets) {
            Ok(()) => {
                println!(
                    "Wrote {} and {} to {} (files 0440, dir 0750).",
                    SECRET_NAMES[0],
                    SECRET_NAMES[1],
                    directory.display()
                );
                println!(
                    "Install the *same two files* on the kraken-ui side so both services \
                     resolve identical secrets."
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("failed to write secret files: {error}");
                ExitCode::FAILURE
            }
        },
        None => {
            for (name, value) in &secrets {
                println!("{name}={value}");
            }
            ExitCode::SUCCESS
        }
    }
}

fn generate_secret() -> String {
    let mut bytes = [0_u8; SECRET_BYTES];
    orion::util::secure_rand_bytes(&mut bytes).expect("system RNG must be available");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn write_secret_files(directory: &Path, secrets: &[(&str, String)]) -> std::io::Result<()> {
    std::fs::create_dir_all(directory)?;
    restrict_directory(directory)?;
    for (name, value) in secrets {
        let path = directory.join(name);
        std::fs::write(&path, value)?;
        restrict_file(&path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o750))
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o440))
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn print_help() {
    eprintln!(
        "rorschach_keygen — generate KrakenWAF rule-management secrets\n\n\
         USAGE:\n  \
         rorschach_keygen            Print NAME=value lines to stdout\n  \
         rorschach_keygen --write    Write files under {DEFAULT_SECRETS_DIR}\n  \
         rorschach_keygen --dir DIR  Write files under DIR\n"
    );
}
