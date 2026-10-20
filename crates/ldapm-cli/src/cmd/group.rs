use ldapm_core::Result;
use ldapm_core::session::MemberAttr;

use crate::cli::GroupCmd;
use crate::ctx::Ctx;
use crate::output;

pub async fn run(ctx: &Ctx, cmd: GroupCmd) -> Result<()> {
    let session = ctx.session().await?;
    match cmd {
        GroupCmd::List => {
            let groups = session.list_groups().await?;
            if ctx.json {
                output::json(&groups);
            } else {
                let rows: Vec<Vec<String>> = groups
                    .iter()
                    .map(|g| vec![g.cn.clone(), output::opt(&g.gid_number), g.member_count.to_string()])
                    .collect();
                output::table(&["CN", "GID", "MEMBERS"], &rows);
            }
        }
        GroupCmd::Show { cn } => {
            let group = session.get_group(&cn).await?;
            if ctx.json {
                output::json(&group);
            } else {
                let dangling = group.members.iter().filter(|m| !m.exists).count();
                let classes: Vec<&str> = group
                    .object_classes
                    .iter()
                    .map(String::as_str)
                    .filter(|c| !c.eq_ignore_ascii_case("top"))
                    .collect();
                output::fields(&[
                    ("dn", group.dn.clone()),
                    ("cn", group.cn.clone()),
                    ("objectClass", classes.join(", ")),
                    ("gidNumber", output::opt(&group.gid_number)),
                    ("description", output::opt(&group.description)),
                    (
                        "members",
                        match dangling {
                            0 => group.members.len().to_string(),
                            n => format!("{} ({n} dangling)", group.members.len()),
                        },
                    ),
                ]);
                let w = group.members.iter().map(|m| m.value.chars().count()).max().unwrap_or(0);
                for m in &group.members {
                    match (m.exists, m.attr) {
                        (true, _) => println!("  {}", m.value),
                        (false, MemberAttr::MemberUid) => println!("  {:<w$}  ! no such user", m.value),
                        (false, _) => println!("  {:<w$}  ! no such entry", m.value),
                    }
                }
            }
        }
    }
    session.close().await;
    Ok(())
}
