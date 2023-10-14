use rsdsl_dslite::{Error, Result};

use std::fs::File;
use std::net::{Ipv6Addr, SocketAddr};
use std::thread;
use std::time::Duration;

use ipnet::Ipv6Net;
use rsdsl_netlinkd_sys::IpIp6;
use rsdsl_pd_config::PdConfig;
use signal_hook::{consts::SIGUSR1, iterator::Signals};
use sysinfo::{ProcessExt, Signal, System, SystemExt};
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

const MAX_ATTEMPTS: usize = 3;
const BACKOFF: u64 = 900;

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
        *tnl = Some(IpIp6::new("dslite0", "ppp0", local, remote)?);

        for netlinkd in System::default().processes_by_exact_name("/bin/rsdsl_netlinkd") {
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
    Ok(*addr)
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
