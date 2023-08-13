use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::thread;
use std::time::Duration;

use ipnet::Ipv6Net;
use rsdsl_dslite::{Error, Result};
use rsdsl_ip_config::DsConfig;
use rsdsl_netlinkd::{addr, link, route};
use rsdsl_netlinkd_sys::IpIp6;
use rsdsl_pd_config::PdConfig;
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

const ADDR4_AFTR: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 1);
const ADDR4_B4: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 2);

const MAX_ATTEMPTS: usize = 3;

fn main() -> Result<()> {
    println!("wait for up ppp0");
    link::wait_up("ppp0".into())?;

    let pd_config = Path::new(rsdsl_pd_config::LOCATION);

    println!("wait for dhcp6");
    while !pd_config.exists() {
        thread::sleep(Duration::from_secs(8));
    }

    let mut file = File::open(rsdsl_pd_config::LOCATION)?;
    let pdconfig: PdConfig = serde_json::from_reader(&mut file)?;

    if let Some(ref aftr) = pdconfig.aftr {
        let local = local_address(&pdconfig)?;
        let remote = multitry_resolve6(&pdconfig, aftr)?;
        let _tnl = IpIp6::new("dslite0", "ppp0", local, remote)?;

        configure_dslite();
    } else {
        println!("no aftr");
    }

    loop {
        thread::sleep(Duration::MAX);
    }
}

fn configure_dslite() {
    match configure_dslite0() {
        Ok(_) => println!("configure dslite0"),
        Err(e) => println!("can't configure dslite0: {}", e),
    }
}

fn configure_dslite0() -> Result<()> {
    link::up("dslite0".into())?;

    addr::flush("dslite0".into())?;
    addr::add("dslite0".into(), ADDR4_B4.into(), 29)?;

    let mut file = File::open(rsdsl_ip_config::LOCATION)?;
    let dsconfig: DsConfig = serde_json::from_reader(&mut file)?;

    // Check for native connectivity to avoid breaking netlinkd.
    if dsconfig.v4.is_none() {
        route::add4(Ipv4Addr::UNSPECIFIED, 0, Some(ADDR4_AFTR), "dslite0".into())?;
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
                    println!("{}", e)
                }
            }
        }

        thread::sleep(Duration::from_secs(8));
    }

    unreachable!()
}
