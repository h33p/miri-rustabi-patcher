use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process::*;

const CHECK_ARGUMENT_COMPAT: &str = "_RNvMNtNtCs4nIGpMcZwJt_16rustc_const_eval9interpret10terminatorINtNtB4_12eval_context8InterpCxNtNtCsbqq2wIJMT6T_4miri7machine9EvaluatorE21check_argument_compatB1x_";

const X64_SEARCH_PATTERN: &[u8] = b"\x48\x39\xce";
const X64_REPLACE_PATTERN: &[u8] = b"\x48\x39\xf6";

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    let bin = env::args()
        .into_iter()
        .nth(1)
        .ok_or("Please provide binary to patch")?;

    let mut cmd = Command::new("readelf");
    cmd.args(&["-Ws", &bin]);

    let output = cmd.output()?;

    if !output.status.success() {
        eprintln!("{}", std::str::from_utf8(&output.stderr)?);
        Err("patch failed")?
    }

    let out = std::str::from_utf8(&output.stdout)?.to_string();

    let addr = out
        .lines()
        .filter(|l| l.contains(CHECK_ARGUMENT_COMPAT))
        .filter_map(|l| l.split_whitespace().nth(1))
        .map(|l| usize::from_str_radix(l, 16))
        .next()
        .ok_or("Value not found")??;

    let mut f = File::open(&bin)?;

    let mut bytes = vec![];
    f.read_to_end(&mut bytes)?;

    let mut f_out = File::create(format!("{}.patched", bin))?;

    for i in (addr..(bytes.len() - X64_SEARCH_PATTERN.len())).take(0x100) {
        let buf = &mut bytes[i..][..X64_SEARCH_PATTERN.len()];
        if buf == X64_SEARCH_PATTERN {
            buf.copy_from_slice(X64_REPLACE_PATTERN);
            f_out.write_all(&bytes)?;
            return Ok(());
        }
    }

    Err("Could not patch".into())
}
