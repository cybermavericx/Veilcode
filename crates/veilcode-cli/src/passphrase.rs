//! Passphrase input (D82): one stdin line with `--passphrase-stdin`,
//! otherwise an rpassword prompt on the terminal (it reads the TTY, never
//! stdin). A new vault asks twice interactively, or reads one line (D17).

use anyhow::{Result, anyhow, bail};
use std::io::{BufRead, Read};

/// Buffer size for the stdin passphrase line, newline included.
const LINE_MAX: usize = 1024;
use veilcode_core::SecretString;

/// The passphrase of an existing vault.
pub fn read(from_stdin: bool) -> Result<SecretString> {
    if from_stdin {
        stdin_line()
    } else {
        prompt("Vault passphrase: ")
    }
}

/// The passphrase of a new vault: asked twice on the terminal (must match).
pub fn read_new(from_stdin: bool) -> Result<SecretString> {
    if from_stdin {
        return stdin_line();
    }
    let first = prompt("New vault passphrase (at least 12 characters): ")?;
    let second = prompt("Repeat the passphrase: ")?;
    if first != second {
        bail!("passphrases do not match");
    }
    Ok(first)
}

/// Exactly one line from stdin, without its `\n` or `\r\n`.
fn stdin_line() -> Result<SecretString> {
    // D89: pre-allocated and read through `take`, so it never reallocates
    // (a reallocation would leave an unwiped copy behind).
    let mut line = String::with_capacity(LINE_MAX);
    let read = std::io::stdin()
        .lock()
        .take(LINE_MAX as u64)
        .read_line(&mut line);
    let too_long = line.len() == LINE_MAX && !line.ends_with('\n');
    // Wrap at once so the buffer is zeroized on every path.
    let mut secret_len = line.len();
    if line.ends_with('\n') {
        secret_len -= 1;
        if line[..secret_len].ends_with('\r') {
            secret_len -= 1;
        }
    }
    line.truncate(secret_len);
    let secret = SecretString::new(line);
    match read {
        Ok(0) => bail!("no passphrase on stdin"),
        Ok(_) if too_long => bail!("passphrase line longer than {} bytes", LINE_MAX - 2),
        Ok(_) => Ok(secret),
        Err(e) => bail!("cannot read the passphrase from stdin: {}", e.kind()),
    }
}

/// A hidden prompt on the terminal.
fn prompt(text: &str) -> Result<SecretString> {
    let pass = rpassword::prompt_password(text)
        .map_err(|_| anyhow!("no terminal; use --passphrase-stdin"))?;
    Ok(SecretString::new(pass))
}
