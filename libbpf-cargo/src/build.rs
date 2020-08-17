use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Result};
use semver::Version;

use crate::metadata;
use crate::metadata::UnprocessedProg;

fn check_progs(progs: &[UnprocessedProg]) -> Result<()> {
    let mut set = HashSet::with_capacity(progs.len());
    for prog in progs {
        // OK to unwrap() file_name() b/c we already checked earlier that this is a valid file
        let dest = prog
            .out
            .as_path()
            .join(prog.path.as_path().file_name().unwrap());
        if !set.insert(dest) {
            bail!(
                "Duplicate prog={} detected",
                prog.path.as_path().file_name().unwrap().to_string_lossy()
            );
        }
    }

    Ok(())
}

fn check_clang(debug: bool, clang: &Path, skip_version_checks: bool) -> Result<()> {
    let output = Command::new(clang.as_os_str()).arg("--version").output()?;

    if !output.status.success() {
        bail!("Failed to execute clang binary");
    }

    if skip_version_checks {
        return Ok(());
    }

    // Example output:
    //
    //     clang version 10.0.0
    //     Target: x86_64-pc-linux-gnu
    //     Thread model: posix
    //     InstalledDir: /bin
    //
    let output = String::from_utf8_lossy(&output.stdout);
    let version_str = output
        .split('\n')
        .next()
        .ok_or_else(|| anyhow!("Invalid version format"))?
        .split(' ')
        .nth(2)
        .ok_or_else(|| anyhow!("Invalid version format"))?;

    let version = Version::parse(version_str)?;
    if debug {
        println!("{} is version {}", clang.display(), version);
    }

    if version < Version::parse("10.0.0").unwrap() {
        bail!(
            "version {} is too old. Use --skip-clang-version-checks to skip verion check",
            version
        );
    }

    Ok(())
}

/// We're essentially going to run:
///
///     clang -g -O2 -target bpf -c -D__TARGET_ARCH_$(ARCH) runqslower.bpf.c -o runqslower.bpf.o
///
/// for each prog.
fn compile(debug: bool, progs: &[UnprocessedProg], clang: &Path) -> Result<()> {
    let arch = if std::env::consts::ARCH == "x86_64" {
        "x86"
    } else {
        std::env::consts::ARCH
    };

    for prog in progs {
        let dest_name = if let Some(f) = prog.path.as_path().file_stem() {
            let mut stem = f.to_os_string();
            stem.push(".o");
            stem
        } else {
            bail!(
                "Could not calculate destination name for prog={}",
                prog.path.as_path().display()
            );
        };
        let mut dest_path = prog.out.clone();
        dest_path.push(&dest_name);

        fs::create_dir_all(prog.out.as_path())?;

        if debug {
            println!("Building {}", prog.path.display());
        }

        let output = Command::new(clang.as_os_str())
            .arg("-g")
            .arg("-O2")
            .arg("-target")
            .arg("bpf")
            .arg("-c")
            .arg(format!("-D__TARGET_ARCH_{}", arch))
            .arg(prog.path.as_path().as_os_str())
            .arg("-o")
            .arg(dest_path)
            .output()?;

        if !output.status.success() {
            bail!(
                "Failed to compile prog={} with status={}\n \
                stdout=\n \
                {}\n \
                stderr=\n \
                {}\n",
                dest_name.to_string_lossy(),
                output.status,
                String::from_utf8(output.stdout).unwrap(),
                String::from_utf8(output.stderr).unwrap()
            )
        }
    }

    Ok(())
}

pub fn build(
    debug: bool,
    manifest_path: Option<&PathBuf>,
    clang: &Path,
    skip_clang_version_checks: bool,
) -> i32 {
    let to_compile = match metadata::get(debug, manifest_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", e);
            return 1;
        }
    };

    if debug && !to_compile.is_empty() {
        println!("Found bpf progs to compile:");
        for prog in &to_compile {
            println!("\t{:?}", prog);
        }
    } else if to_compile.is_empty() {
        eprintln!("Did not find any bpf progs to compile");
        return 1;
    }

    if let Err(e) = check_progs(&to_compile) {
        eprintln!("{}", e);
        return 1;
    }

    if let Err(e) = check_clang(debug, clang, skip_clang_version_checks) {
        eprintln!("{} is invalid: {}", clang.display(), e);
        return 1;
    }

    match compile(debug, &to_compile, clang) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Failed to compile progs: {}", e);
            1
        }
    }
}
