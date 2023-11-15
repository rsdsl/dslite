use std::fs::File;
use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::thread;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::Resolver;
use ipnet::Ipv6Net;
use rsdsl_netlinklib::tunnel::IpIp6;
use rsdsl_pd_config::PdConfig;
use signal_hook::{consts::SIGUSR1, iterator::Signals};
use sysinfo::{ProcessExt, Signal, System, SystemExt};
use thiserror::Error;

const MAX_ATTEMPTS: usize = 3;
const BACKOFF: u64 = 900;

#[derive(Debug, Error)]
pub enum Error {
    #[error("no address associated with aftr name")]
    NoDnsRecord,
    #[error("not enough ipv6 subnets")]
    NotEnoughIpv6Subnets,

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid prefix length: {0}")]
    IpnetPrefixLen(#[from] ipnet::PrefixLenError),
    #[error("netlinklib error: {0}")]
    Netlinklib(#[from] rsdsl_netlinklib::Error),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("hickory_resolver resolve error: {0}")]
    TrustDnsResolverResolve(#[from] hickory_resolver::error::ResolveError),
}

pub type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    println!("[info] init");

    let mut tnl = None;

    let mut signals = Signals::new([SIGUSR1])?;
    for _ in signals.forever() {
        logic(&mut tnl)?;
    }

    unreachable!()
}

fn logic(tnl: &mut Option<IpIp6>) -> Result<()> {
    *tnl = None; // Delete old tunnel.

    let mut file = File::open(rsdsl_pd_config::LOCATION)?;
    let pdconfig: PdConfig = serde_json::from_reader(&mut file)?;

    if let Some(ref aftr) = pdconfig.aftr {
        let local = local_address(&pdconfig)?;
        let remote = multitry_resolve6(&pdconfig, aftr)?;
        *tnl = Some(IpIp6::new(
            "dslite0".to_string(),
            "ppp0".to_string(),
            local,
            remote,
        )?);

        for netlinkd in System::new_all().processes_by_exact_name("rsdsl_netlinkd") {
            netlinkd.kill_with(Signal::User1);
        }

        println!("[info] init ds-lite tunnel {} <=> {}", local, remote);
    } else {
        println!("[info] no aftr");
    }

    Ok(())
}

fn local_address(pdconfig: &PdConfig) -> Result<Ipv6Addr> {
    let prefix = Ipv6Net::new(pdconfig.prefix, pdconfig.len)?.trunc();
    let mut subnets = prefix.subnets(64)?;

    let addr = next_ifid1(&mut subnets)?;
    Ok(addr)
}

fn next_ifid1<T: Iterator<Item = Ipv6Net>>(subnets: &mut T) -> Result<Ipv6Addr> {
    Ok((u128::from(subnets.next().ok_or(Error::NotEnoughIpv6Subnets)?.addr()) + 1).into())
}

fn resolve6(pdconfig: &PdConfig, fqdn: &str) -> Result<Ipv6Addr> {
    let mut cfg = ResolverConfig::new();

    cfg.add_name_server(NameServerConfig::new(
        SocketAddr::new(pdconfig.dns1.into(), 53),
        Protocol::Udp,
    ));
    cfg.add_name_server(NameServerConfig::new(
        SocketAddr::new(pdconfig.dns2.into(), 53),
        Protocol::Udp,
    ));

    let resolver = Resolver::new(cfg, ResolverOpts::default())?;
    let response = resolver.ipv6_lookup(fqdn)?;

    let addr = response.iter().next().ok_or(Error::NoDnsRecord)?;
    Ok(**addr)
}

fn multitry_resolve6(pdconfig: &PdConfig, fqdn: &str) -> Result<Ipv6Addr> {
    for i in 0..MAX_ATTEMPTS {
        match resolve6(pdconfig, fqdn) {
            Ok(v) => return Ok(v),
            Err(e) => {
                if i >= MAX_ATTEMPTS - 1 {
                    return Err(e);
                } else {
                    println!(
                        "[warn] resolve aftr {}: {} (attempt {}/{})",
                        fqdn, e, i, MAX_ATTEMPTS
                    )
                }
            }
        }

        thread::sleep(Duration::from_secs(BACKOFF));
    }

    unreachable!()
}
