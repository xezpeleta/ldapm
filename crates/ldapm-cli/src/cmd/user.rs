use ldapm_core::Result;
use ldapm_core::session::UserStatus;

use crate::cli::UserCmd;
use crate::ctx::Ctx;
use crate::output;

pub async fn run(ctx: &Ctx, cmd: UserCmd) -> Result<()> {
    let session = ctx.session().await?;
    match cmd {
        UserCmd::Show { uid } => {
            let user = session.get_user(&uid).await?;
            if ctx.json {
                output::json(&user);
            } else {
                let groups = if user.groups.is_empty() {
                    "-".to_string()
                } else {
                    user.groups
                        .iter()
                        .map(|g| if g.primary { format!("{} (primary)", g.cn) } else { g.cn.clone() })
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let status = match &user.status {
                    UserStatus::Active => "active".to_string(),
                    UserStatus::Disabled => "DISABLED (permanent lock)".to_string(),
                    UserStatus::LockedOut { since, until } => match until {
                        Some(u) => format!("locked out since {since} until {u} (failed binds)"),
                        None => format!("locked out since {since} (failed binds)"),
                    },
                };
                output::fields(&[
                    ("dn", user.dn.clone()),
                    ("cn", output::opt(&user.cn)),
                    ("mail", output::opt(&user.mail)),
                    ("uidNumber", output::opt(&user.uid_number)),
                    ("gidNumber", output::opt(&user.gid_number)),
                    ("groups", groups),
                    ("status", status),
                    ("policy", user.policy.clone().unwrap_or_else(|| "default".into())),
                    ("pwdReset", if user.pwd_reset { "yes" } else { "no" }.into()),
                    ("pwdChanged", output::opt(&user.pwd_changed)),
                    ("failed binds", user.failed_binds.to_string()),
                ]);
            }
        }
        UserCmd::Search { term } => {
            let hits = session.search_users(&term).await?;
            if ctx.json {
                output::json(&hits);
            } else {
                let rows: Vec<Vec<String>> = hits
                    .iter()
                    .map(|h| vec![output::opt(&h.uid), output::opt(&h.cn), output::opt(&h.mail)])
                    .collect();
                output::table(&["UID", "CN", "MAIL"], &rows);
            }
        }
    }
    session.close().await;
    Ok(())
}
