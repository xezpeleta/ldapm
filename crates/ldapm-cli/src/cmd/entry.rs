use ldapm_core::Result;
use ldapm_core::session::{SearchField, Value};

use crate::cli::{EntryCmd, Field};
use crate::ctx::Ctx;
use crate::output;

pub async fn run(ctx: &Ctx, cmd: EntryCmd) -> Result<()> {
    let session = ctx.session().await?;
    let base = session.conventions().base_dn.clone();
    match cmd {
        EntryCmd::Ls { dn } => {
            let children = session.list_children(dn.as_deref().unwrap_or(&base)).await?;
            if ctx.json {
                output::json(&children);
            } else {
                for n in &children.nodes {
                    let marker = if n.has_children == Some(true) { "  +" } else { "" };
                    println!("  {}{marker}", n.rdn);
                }
                if children.truncated {
                    eprintln!(
                        "warning: listing truncated at {} entries by the server's size limit; \
                         use `entry search` to narrow it down",
                        children.nodes.len()
                    );
                }
            }
        }
        EntryCmd::Show { dn, operational } => {
            let entry = session.get_entry(&dn, operational).await?;
            if ctx.json {
                output::json(&entry);
            } else {
                println!("dn: {}", entry.dn);
                for attr in &entry.attrs {
                    for v in &attr.values {
                        match v {
                            Value::Text { value } => println!("{}: {}", attr.name, printable(value)),
                            Value::Binary { len } => println!("{}: <binary, {len} bytes>", attr.name),
                            Value::Hidden => println!("{}: <hidden>", attr.name),
                        }
                    }
                }
            }
        }
        EntryCmd::Search { term, base: search_base, by } => {
            let field = match by {
                Field::Uid => SearchField::Uid,
                Field::Cn => SearchField::Cn,
                Field::Mail => SearchField::Mail,
                Field::Any => SearchField::Any,
            };
            let hits = session.search(search_base.as_deref().unwrap_or(&base), &term, field).await?;
            if ctx.json {
                output::json(&hits);
            } else {
                let rows: Vec<Vec<String>> = hits
                    .iter()
                    .map(|h| vec![h.dn.clone(), output::opt(&h.cn), output::opt(&h.mail)])
                    .collect();
                output::table(&["DN", "CN", "MAIL"], &rows);
            }
        }
    }
    session.close().await;
    Ok(())
}

/// Keep terminal output on one line per value.
fn printable(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '·' } else { c }).collect()
}
