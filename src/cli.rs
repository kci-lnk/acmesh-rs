use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::{collections::HashMap, path::PathBuf};

#[derive(Parser, Debug, Clone)]
#[command(name = "acme.sh", version, disable_help_subcommand = true)]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[arg(short = 'd', long = "domain", global = true)]
    pub domains: Vec<String>,
    #[arg(long, global = true)]
    pub dns: Option<String>,
    #[arg(long, global = true, default_value_t = 10)]
    pub dnssleep: u64,
    #[arg(long, global = true)]
    pub home: Option<PathBuf>,
    #[arg(long, global = true)]
    pub config_home: Option<PathBuf>,
    #[arg(long, global = true)]
    pub cert_home: Option<PathBuf>,
    #[arg(long, global = true)]
    pub email: Option<String>,
    #[arg(long, global = true)]
    pub server: Option<String>,
    #[arg(long, global = true)]
    pub staging: bool,
    #[arg(long, global = true)]
    pub ecc: bool,
    #[arg(long, global = true)]
    pub keylength: Option<String>,
    #[arg(long, global = true)]
    pub accountkeylength: Option<String>,
    #[arg(long, global = true)]
    pub accountkey: Option<PathBuf>,
    #[arg(long, global = true)]
    pub accountconf: Option<PathBuf>,
    #[arg(long, global = true)]
    pub domainconf: Option<PathBuf>,
    #[arg(long, global = true)]
    pub csr: Option<PathBuf>,
    #[arg(long, global = true)]
    pub cert_file: Option<PathBuf>,
    #[arg(long, global = true)]
    pub key_file: Option<PathBuf>,
    #[arg(long, global = true)]
    pub ca_file: Option<PathBuf>,
    #[arg(long, global = true)]
    pub fullchain_file: Option<PathBuf>,
    #[arg(long, global = true)]
    pub password: Option<String>,
    #[arg(long, global = true)]
    pub force: bool,
    #[arg(long, global = true)]
    pub insecure: bool,
    #[arg(long, global = true)]
    pub debug: bool,
    #[arg(long, global = true)]
    pub no_color: bool,
    /// Do not persist DNS provider credentials in account.conf.
    #[arg(long, global = true)]
    pub no_save_credentials: bool,
    #[arg(long, global = true, default_value_t = 0)]
    pub revoke_reason: u8,
    /// Provider credentials. Use NAME=VALUE; repeat as needed.
    #[arg(long = "env", global = true, value_parser = parse_env)]
    pub env: Vec<(String, String)>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    Issue,
    Renew,
    InstallCert,
    Revoke,
    Remove,
    List,
    Info,
    RegisterAccount,
    CreateAccountKey,
    CreateDomainKey,
    CreateCsr,
    SignCsr,
    ShowCsr,
    #[cfg(feature = "pkcs12")]
    ToPkcs12,
    ToPkcs8,
    Version,
    Help,
}

fn parse_env(s: &str) -> Result<(String, String), String> {
    let (k, v) = s.split_once('=').ok_or("expected NAME=VALUE")?;
    if k.trim().is_empty() {
        return Err("environment name cannot be empty".into());
    }
    Ok((k.trim().to_string(), v.to_string()))
}

pub fn print_help() {
    println!("Use --help to see supported commands. DNS credentials use --env NAME=VALUE.");
}

/// Translate acme.sh's operation flags into clap subcommands while leaving all
/// option flags untouched. This keeps `--issue -d example.com` compatible.
pub fn compatible_argv() -> Vec<String> {
    translate_argv(std::env::args().collect())
}

fn translate_argv(mut raw: Vec<String>) -> Vec<String> {
    let operations = [
        ("--issue", "issue"),
        ("--renew", "renew"),
        ("--install-cert", "install-cert"),
        ("--revoke", "revoke"),
        ("--remove", "remove"),
        ("--list", "list"),
        ("--info", "info"),
        ("--register-account", "register-account"),
        ("--create-account-key", "create-account-key"),
        ("--create-domain-key", "create-domain-key"),
        ("--create-csr", "create-csr"),
        ("--sign-csr", "sign-csr"),
        ("--show-csr", "show-csr"),
        #[cfg(feature = "pkcs12")]
        ("--to-pkcs12", "to-pkcs12"),
        ("--to-pkcs8", "to-pkcs8"),
    ];
    if let Some(index) = raw
        .iter()
        .position(|value| operations.iter().any(|(flag, _)| value == flag))
    {
        let command = operations
            .iter()
            .find(|(flag, _)| raw[index] == *flag)
            .unwrap()
            .1;
        raw.remove(index);
        raw.insert(1, command.to_string());
    }
    raw
}

pub async fn run(args: Args) -> Result<()> {
    let store = crate::storage::Store::new(
        args.home.clone(),
        args.config_home.clone(),
        args.cert_home.clone(),
        args.accountconf.clone(),
        args.domainconf.clone(),
    )?;
    match args.command.as_ref().unwrap() {
        Command::Version => println!("rust-acmesh {}", env!("CARGO_PKG_VERSION")),
        Command::Help => print_help(),
        Command::CreateAccountKey => {
            let p = args
                .accountkey
                .unwrap_or_else(|| store.home.join("account.key"));
            crate::crypto::create_account_key(&p, args.ecc, args.accountkeylength.as_deref())?;
            println!("saved {}", p.display());
        }
        Command::CreateDomainKey => {
            let d = one_domain(&args)?;
            let p = store.domain_dir(&d).join("domain.key");
            crate::crypto::create_domain_key(&p, args.ecc, args.keylength.as_deref())?;
            println!("saved {}", p.display());
        }
        Command::Issue => crate::acme::issue(&args, &store).await?,
        Command::Renew => crate::acme::renew(&args, &store).await?,
        Command::InstallCert => crate::storage::install_cert(&args, &store)?,
        Command::List => crate::storage::list(&store)?,
        Command::Info => crate::storage::info(&args, &store)?,
        Command::Remove => crate::storage::remove(&args, &store)?,
        Command::RegisterAccount => crate::acme::register_account(&args, &store).await?,
        Command::CreateCsr => {
            let d = one_domain(&args)?;
            let key = store.domain_dir(&d).join("domain.key");
            if !key.exists() {
                crate::crypto::create_domain_key(&key, args.ecc, args.keylength.as_deref())?;
            }
            let out = args
                .cert_file
                .clone()
                .unwrap_or_else(|| store.domain_dir(&d).join("domain.csr"));
            crate::crypto::create_csr(&key, &args.domains, &out)?;
            println!("saved {}", out.display());
        }
        Command::ShowCsr => {
            let p = args.cert_file.clone().context("--cert-file is required")?;
            println!("{}", crate::crypto::show_csr(&p)?);
        }
        Command::ToPkcs8 => crate::storage::to_pkcs8(&args, &store)?,
        Command::Revoke => crate::acme::revoke(&args, &store).await?,
        Command::SignCsr => {
            let mut request = args.clone();
            let csr = request
                .csr
                .as_ref()
                .context("--csr is required with --sign-csr")?;
            if request.domains.is_empty() {
                request.domains = crate::crypto::csr_domains(csr)?;
            }
            crate::acme::issue(&request, &store).await?
        }
        #[cfg(feature = "pkcs12")]
        Command::ToPkcs12 => crate::storage::to_pkcs12(&args, &store)?,
    }
    Ok(())
}

pub fn one_domain(args: &Args) -> Result<String> {
    args.domains
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("-d/--domain is required"))
}
pub fn credentials(args: &Args) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = args.env.iter().cloned().collect();
    let names = [
        "CF_Token",
        "CF_Zone_ID",
        "CF_Account_ID",
        "CF_Key",
        "CF_Email",
        "DP_Id",
        "DP_Key",
        "DP_Domain",
        "Ali_Key",
        "Ali_Secret",
        "Ali_Domain",
        "Tencent_SecretId",
        "Tencent_SecretKey",
        "GD_Key",
        "GD_Secret",
        "GD_Domain",
        "HUAWEICLOUD_Username",
        "HUAWEICLOUD_Password",
        "HUAWEICLOUD_DomainName",
        "HUAWEICLOUD_Region",
        "HUAWEICLOUD_ProjectName",
        "PORKBUN_API_KEY",
        "PORKBUN_SECRET_API_KEY",
        "PORKBUN_DOMAIN",
        "BAIDU_ACCESS_KEY_ID",
        "BAIDU_SECRET_ACCESS_KEY",
        "BAIDU_DOMAIN",
        "root_domain",
        "Dynu_ClientId",
        "Dynu_Secret",
        "DYNV6_TOKEN",
        "DuckDNS_Token",
        "NOIP_USERNAME",
        "NOIP_PASSWORD",
        "EAB_KID",
        "EAB_HMAC_KEY",
    ];
    for name in names {
        if !out.contains_key(name)
            && let Ok(value) = std::env::var(name)
        {
            out.insert(name.into(), value);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_acmesh_operation_flags() {
        let args = translate_argv(vec![
            "rust-acmesh.exe".into(),
            "-d".into(),
            "example.com".into(),
            "--issue".into(),
            "--dnssleep".into(),
            "30".into(),
        ]);
        assert_eq!(
            args,
            vec![
                "rust-acmesh.exe",
                "issue",
                "-d",
                "example.com",
                "--dnssleep",
                "30"
            ]
        );
        let parsed = Args::try_parse_from(args).unwrap();
        assert!(matches!(parsed.command, Some(Command::Issue)));
        assert_eq!(parsed.dnssleep, 30);
    }
}
