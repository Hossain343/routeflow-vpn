//! Compact in-memory matchers and the routing decision.
//!
//! Precedence (first match wins) for a domain:
//!   1 router_divert.json  -> ROUTER        4 proxy category (optional) -> VPN
//!   2 vpn_divert.json     -> VPN           5 iran-hosted-domains list  -> ROUTER
//!   3 ads list (optional) -> BLOCK         6 *.ir (optional)           -> ROUTER
//!                                          7 everything else           -> VPN (no lookups)
//! and for an IP: router_divert, vpn_divert, LAN, RIPE Iran ranges (-> ROUTER), else VPN.
use ahash::AHashSet;
use std::net::IpAddr;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Router,
    Vpn,
    Block,
}

impl Route {
    pub fn as_str(&self) -> &'static str {
        match self {
            Route::Router => "ROUTER",
            Route::Vpn => "VPN",
            Route::Block => "BLOCK",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Decision {
    pub route: Route,
    pub reason: &'static str,
}

impl Decision {
    fn new(route: Route, reason: &'static str) -> Decision {
        Decision { route, reason }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Flags {
    pub ads_block: bool,
    pub use_proxy_category: bool,
    pub domestic_tld_direct: bool,
}

const MAX_KEYWORDS: usize = 512;

/// Suffix set (`example.com` matches `a.b.example.com`), exact set, and a few keywords.
/// Lookup is one hash probe per label of the host: no allocation, no locking.
#[derive(Default)]
pub struct DomainSet {
    suffix: AHashSet<Box<str>>,
    full: AHashSet<Box<str>>,
    keywords: Vec<Box<str>>,
}

impl DomainSet {
    pub fn add_suffix(&mut self, d: &str) {
        self.suffix.insert(d.into());
    }
    pub fn add_full(&mut self, d: &str) {
        self.full.insert(d.into());
    }
    /// false when the keyword table is full (keywords are scanned linearly, so they are capped)
    pub fn add_keyword(&mut self, k: &str) -> bool {
        if self.keywords.len() >= MAX_KEYWORDS {
            return false;
        }
        self.keywords.push(k.into());
        true
    }
    pub fn len(&self) -> usize {
        self.suffix.len() + self.full.len() + self.keywords.len()
    }
    /// `host` must already be lower-case without a trailing dot.
    pub fn matches(&self, host: &str) -> bool {
        if self.len() == 0 {
            return false;
        }
        if self.full.contains(host) {
            return true;
        }
        let mut h = host;
        loop {
            if self.suffix.contains(h) {
                return true;
            }
            match h.find('.') {
                Some(i) => h = &h[i + 1..],
                None => break,
            }
        }
        self.keywords.iter().any(|k| host.contains(&**k))
    }
}

/// Sorted, merged ranges; lookup is a binary search.
#[derive(Default)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpSet {
    /// Accepts a single IP or a CIDR. Call `finish()` once after the last add.
    pub fn add_cidr(&mut self, s: &str) -> Result<(), String> {
        let s = s.trim();
        let (ip_part, len_part) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let ip: IpAddr = ip_part
            .parse()
            .map_err(|_| format!("'{}' is not an IP address or CIDR", s))?;
        match ip {
            IpAddr::V4(a) => {
                let len: u32 = match len_part {
                    Some(l) => l.parse().map_err(|_| format!("bad prefix length in '{}'", s))?,
                    None => 32,
                };
                if len > 32 {
                    return Err(format!("prefix length too large in '{}'", s));
                }
                let mask: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len) };
                let start = u32::from(a) & mask;
                self.v4.push((start, start | !mask));
            }
            IpAddr::V6(a) => {
                let len: u32 = match len_part {
                    Some(l) => l.parse().map_err(|_| format!("bad prefix length in '{}'", s))?,
                    None => 128,
                };
                if len > 128 {
                    return Err(format!("prefix length too large in '{}'", s));
                }
                let mask: u128 = if len == 0 { 0 } else { u128::MAX << (128 - len) };
                let start = u128::from(a) & mask;
                self.v6.push((start, start | !mask));
            }
        }
        Ok(())
    }

    pub fn finish(&mut self) {
        self.v4.sort_unstable();
        self.v6.sort_unstable();
        let mut m4: Vec<(u32, u32)> = Vec::with_capacity(self.v4.len());
        for &(a, b) in &self.v4 {
            let touches = match m4.last() {
                Some(last) => a <= last.1.saturating_add(1),
                None => false,
            };
            if touches {
                if let Some(last) = m4.last_mut() {
                    if b > last.1 {
                        last.1 = b;
                    }
                }
            } else {
                m4.push((a, b));
            }
        }
        let mut m6: Vec<(u128, u128)> = Vec::with_capacity(self.v6.len());
        for &(a, b) in &self.v6 {
            let touches = match m6.last() {
                Some(last) => a <= last.1.saturating_add(1),
                None => false,
            };
            if touches {
                if let Some(last) = m6.last_mut() {
                    if b > last.1 {
                        last.1 = b;
                    }
                }
            } else {
                m6.push((a, b));
            }
        }
        self.v4 = m4;
        self.v6 = m6;
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => {
                let x = u32::from(a);
                let i = self.v4.partition_point(|r| r.0 <= x);
                i > 0 && x <= self.v4[i - 1].1
            }
            IpAddr::V6(a) => {
                if let Some(v4) = a.to_ipv4_mapped() {
                    return self.contains(IpAddr::V4(v4));
                }
                let x = u128::from(a);
                let i = self.v6.partition_point(|r| r.0 <= x);
                i > 0 && x <= self.v6[i - 1].1
            }
        }
    }
}

#[derive(Default)]
pub struct DivertSet {
    pub domains: DomainSet,
    pub ips: IpSet,
}

#[derive(Default)]
pub struct Diverts {
    pub router: DivertSet,
    pub vpn: DivertSet,
}

#[derive(Default, Clone, Debug)]
pub struct ListInfo {
    pub source: String,
    pub iran: usize,
    pub ads: usize,
    pub proxy: usize,
    pub regex_skipped: usize,
    pub notes: Vec<String>,
}

#[derive(Default)]
pub struct ListSet {
    pub iran: DomainSet,
    pub ads: DomainSet,
    pub proxy: DomainSet,
    pub info: ListInfo,
}

fn lan() -> &'static IpSet {
    static LAN: OnceLock<IpSet> = OnceLock::new();
    LAN.get_or_init(|| {
        let mut s = IpSet::default();
        for c in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "100.64.0.0/10",
            "fc00::/7",
            "fe80::/10",
        ] {
            let _ = s.add_cidr(c);
        }
        s.finish();
        s
    })
}

pub fn decide_host(host: &str, lists: &ListSet, dv: &Diverts, f: &Flags) -> Decision {
    if dv.router.domains.matches(host) {
        return Decision::new(Route::Router, "router_divert");
    }
    if dv.vpn.domains.matches(host) {
        return Decision::new(Route::Vpn, "vpn_divert");
    }
    if f.ads_block && lists.ads.matches(host) {
        return Decision::new(Route::Block, "ads-block");
    }
    if f.use_proxy_category && lists.proxy.matches(host) {
        return Decision::new(Route::Vpn, "proxy-category");
    }
    if lists.iran.matches(host) {
        return Decision::new(Route::Router, "iran-list");
    }
    if f.domestic_tld_direct && (host == "ir" || host.ends_with(".ir")) {
        return Decision::new(Route::Router, ".ir");
    }
    Decision::new(Route::Vpn, "default")
}

pub fn decide_ip(ip: IpAddr, dv: &Diverts, ir: &IpSet) -> Decision {
    if dv.router.ips.contains(ip) {
        return Decision::new(Route::Router, "router_divert");
    }
    if dv.vpn.ips.contains(ip) {
        return Decision::new(Route::Vpn, "vpn_divert");
    }
    if lan().contains(ip) {
        return Decision::new(Route::Router, "lan");
    }
    if ir.contains(ip) {
        return Decision::new(Route::Router, "iran-ip");
    }
    Decision::new(Route::Vpn, "default")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> IpSet {
        let mut s = IpSet::default();
        for i in items {
            s.add_cidr(i).unwrap();
        }
        s.finish();
        s
    }

    #[test]
    fn ip_ranges_merge_and_match() {
        let s = set(&["5.200.0.0/16", "5.201.0.0/16", "2.144.0.0/14", "1.2.3.4"]);
        assert!(s.contains("5.200.9.9".parse().unwrap()));
        assert!(s.contains("5.201.255.255".parse().unwrap()));
        assert!(!s.contains("5.202.0.0".parse().unwrap()));
        assert!(s.contains("2.147.255.255".parse().unwrap()));
        assert!(!s.contains("2.148.0.0".parse().unwrap()));
        assert!(s.contains("1.2.3.4".parse().unwrap()));
        assert!(!s.contains("1.2.3.5".parse().unwrap()));
        assert!(s.len() <= 3);
    }

    #[test]
    fn ipv6_and_mapped() {
        let s = set(&["2a01:5ec0::/32", "5.200.0.0/16"]);
        assert!(s.contains("2a01:5ec0::1".parse().unwrap()));
        assert!(!s.contains("2a01:5ec1::1".parse().unwrap()));
        assert!(s.contains("::ffff:5.200.1.1".parse().unwrap()));
    }

    #[test]
    fn domain_suffix_full_keyword() {
        let mut d = DomainSet::default();
        d.add_suffix("digikala.com");
        d.add_full("exact.example");
        d.add_keyword("bank");
        assert!(d.matches("digikala.com"));
        assert!(d.matches("www.digikala.com"));
        assert!(!d.matches("notdigikala.com"));
        assert!(d.matches("exact.example"));
        assert!(!d.matches("a.exact.example"));
        assert!(d.matches("my-bank-site.org"));
        assert!(!d.matches("example.org"));
    }

    #[test]
    fn precedence() {
        let mut lists = ListSet::default();
        lists.iran.add_suffix("digikala.com");
        lists.ads.add_suffix("ads.digikala.com");
        lists.proxy.add_suffix("blocked-in-iran.ir");
        let mut dv = Diverts::default();
        dv.router.domains.add_suffix("forced-router.com");
        dv.vpn.domains.add_suffix("forced-vpn.ir");
        dv.vpn.domains.add_suffix("digikala.com");
        let f = Flags { ads_block: true, use_proxy_category: true, domestic_tld_direct: true };
        assert_eq!(decide_host("forced-router.com", &lists, &dv, &f).route, Route::Router);
        assert_eq!(decide_host("forced-vpn.ir", &lists, &dv, &f).route, Route::Vpn);
        // vpn_divert beats the Iran list
        assert_eq!(decide_host("digikala.com", &lists, &dv, &f).reason, "vpn_divert");
        assert_eq!(decide_host("blocked-in-iran.ir", &lists, &dv, &f).reason, "proxy-category");
        assert_eq!(decide_host("snapp.ir", &lists, &dv, &f).reason, ".ir");
        assert_eq!(decide_host("google.com", &lists, &dv, &f).reason, "default");
        let f2 = Flags { ads_block: false, ..f };
        let dv2 = Diverts::default();
        assert_eq!(decide_host("ads.digikala.com", &lists, &dv2, &f2).route, Route::Router);
        assert_eq!(decide_host("ads.digikala.com", &lists, &dv2, &f).route, Route::Block);
    }
}
