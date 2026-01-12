use std::fs::File;
use std::net::{Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;
use std::{fmt, io, thread};

use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::Resolver;
use ipnet::Ipv6Net;
use rsdsl_netlinklib::tunnel::IpIp6;
use rsdsl_pd_config::PdConfig;
use signal_hook::{consts::SIGUSR1, iterator::Signals};
use sysinfo::{ProcessExt, Signal, System, SystemExt};

const MAX_ATTEMPTS: usize = 3;
const BACKOFF: u64 = 30;

#[derive(Debug)]
pub enum Error {
    NoDnsRecord,
    NotEnoughIpv6Subnets,

    Io(io::Error),

    IpnetPrefixLen(ipnet::PrefixLenError),
    Netlinklib(rsdsl_netlinklib::Error),
    SerdeJson(serde_json::Error),
    HickoryResolverResolve(hickory_resolver::error::ResolveError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDnsRecord => write!(f, "no address associated with aftr name")?,
            Self::NotEnoughIpv6Subnets => write!(f, "not enough ipv6 subnets")?,
            Self::Io(e) => write!(f, "io error: {}", e)?,
            Self::IpnetPrefixLen(e) => write!(f, "invalid prefix length: {}", e)?,
            Self::Netlinklib(e) => write!(f, "netlinklib error: {}", e)?,
            Self::SerdeJson(e) => write!(f, "serde_json error: {}", e)?,
            Self::HickoryResolverResolve(e) => write!(f, "hickory_resolver resolve error: {}", e)?,
        }

        Ok(())
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<ipnet::PrefixLenError> for Error {
    fn from(e: ipnet::PrefixLenError) -> Error {
        Error::IpnetPrefixLen(e)
    }
}

impl From<rsdsl_netlinklib::Error> for Error {
    fn from(e: rsdsl_netlinklib::Error) -> Error {
        Error::Netlinklib(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::SerdeJson(e)
    }
}

impl From<hickory_resolver::error::ResolveError> for Error {
    fn from(e: hickory_resolver::error::ResolveError) -> Error {
        Error::HickoryResolverResolve(e)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    eprintln!("[info] init");

    let mut tnl = None;
    let mut last = None;

    logic(&mut tnl, &mut last)?;

    let mut signals = Signals::new([SIGUSR1])?;
    for _ in signals.forever() {
        logic(&mut tnl, &mut last)?;
    }

    unreachable!()
}

fn logic(tnl: &mut Option<IpIp6>, last: &mut Option<(Ipv6Addr, Ipv6Addr)>) -> Result<()> {
    if !Path::new(rsdsl_pd_config::LOCATION).exists() {
        eprintln!("[info] no lease");

        *tnl = None; // Delete tunnel.

        for netlinkd in System::new_all().processes_by_exact_name("rsdsl_netlinkd") {
            netlinkd.kill_with(Signal::User1);
        }

        return Ok(());
    }

    let mut file = File::open(rsdsl_pd_config::LOCATION)?;
    let pdconfig: PdConfig = serde_json::from_reader(&mut file)?;

    if let Some(ref aftr) = pdconfig.aftr {
        let local = local_address(&pdconfig)?;
        let remote = multitry_resolve6(&pdconfig, aftr)?;

        if unchanged(local, remote, last) {
            eprintln!("[info] no change");
            return Ok(());
        }

        *tnl = None; // Delete tunnel first, otherwise creation fails with "file exists".
        *tnl = Some(IpIp6::new(
            "dslite0".to_string(),
            "ppp0".to_string(),
            local,
            remote,
        )?);

        for netlinkd in System::new_all().processes_by_exact_name("rsdsl_netlinkd") {
            netlinkd.kill_with(Signal::User1);
        }

        eprintln!("[info] init ds-lite tunnel {} <=> {}", local, remote);
    } else {
        *tnl = None; // Delete tunnel (if any).

        for netlinkd in System::new_all().processes_by_exact_name("rsdsl_netlinkd") {
            netlinkd.kill_with(Signal::User1);
        }

        eprintln!("[info] no aftr");
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
                    eprintln!(
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

fn unchanged(local: Ipv6Addr, remote: Ipv6Addr, last: &mut Option<(Ipv6Addr, Ipv6Addr)>) -> bool {
    let unchanged = if let Some(last) = last {
        local == last.0 && remote == last.1
    } else {
        false
    };

    *last = Some((local, remote));
    unchanged
}
