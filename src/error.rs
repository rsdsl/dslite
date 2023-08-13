use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not enough ipv6 subnets")]
    NotEnoughIpv6Subnets,
    #[error("no address associated with aftr name")]
    NoDnsRecord,

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("ipnet prefix len: {0}")]
    IpnetPrefixLen(#[from] ipnet::PrefixLenError),
    #[error("rsdsl_netlinkd: {0}")]
    RsdslNetlinkd(#[from] rsdsl_netlinkd::error::Error),
    #[error("rsdsl_netlinkd_sys: {0}")]
    RsdslNetlinkdSys(#[from] rsdsl_netlinkd_sys::Error),
    #[error("serde_json: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("trust_dns_resolver resolve: {0}")]
    TrustDnsResolverResolve(#[from] trust_dns_resolver::error::ResolveError),
}

pub type Result<T> = std::result::Result<T, Error>;
