//! Output helpers: human tables to stdout, JSON with `--json`.

use serde::Serialize;

pub fn json<T: Serialize + ?Sized>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("error: serialising output: {e}"),
    }
}

/// Print rows as left-aligned columns. Column widths fit the widest cell.
pub fn table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let mut out = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                out.push_str(cell);
            } else {
                out.push_str(&format!("{cell:<w$}  ", w = widths[i]));
            }
        }
        println!("{}", out.trim_end());
    };
    line(headers.to_vec());
    for row in rows {
        line(row.iter().map(String::as_str).collect());
    }
}

/// `label: value` lines with aligned values.
pub fn fields(rows: &[(&str, String)]) {
    let w = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0) + 1;
    for (k, v) in rows {
        println!("{:<w$} {v}", format!("{k}:"), w = w);
    }
}

pub fn opt(v: &Option<String>) -> String {
    v.clone().unwrap_or_else(|| "-".into())
}

/// Step results for diagnostic commands, on stdout.
pub fn ok(msg: impl AsRef<str>) {
    println!("✓ {}", msg.as_ref());
}

pub fn fail(msg: impl AsRef<str>) {
    println!("✗ {}", msg.as_ref());
}

pub fn warn(msg: impl AsRef<str>) {
    println!("! {}", msg.as_ref());
}
