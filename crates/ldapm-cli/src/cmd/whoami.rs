use ldapm_core::Result;
use serde::Serialize;

use crate::ctx::Ctx;
use crate::output;

#[derive(Serialize)]
struct WhoAmI<'a> {
    profile: &'a str,
    authz_id: &'a str,
    url: &'a str,
    tls: &'a str,
    tunnel: bool,
}

pub async fn run(ctx: &Ctx) -> Result<()> {
    let (name, _) = ctx.profile(None)?;
    let session = ctx.session().await?;
    let authz = session.whoami().await?;
    let shown = if authz.is_empty() { "anonymous" } else { authz.as_str() };
    if ctx.json {
        let info = session.info();
        output::json(&WhoAmI {
            profile: &name,
            authz_id: shown,
            url: &info.url,
            tls: info.tls,
            tunnel: info.tunnel.is_some(),
        });
    } else {
        println!("{shown}");
    }
    session.close().await;
    Ok(())
}
