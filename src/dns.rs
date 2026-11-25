//! DNS through the modem. Iranian-listed domains must be resolved by the modem's (ISP) DNS and
//! then reached through the real network card; resolving them through the VPN would give wrong
//! answers. Queries leave through a UDP socket that is locked to that card. Answers are cached
//! and concurrent lookups of the same name share one query.
use crate::net::{self, NicInfo};
use crate::util::random_u16;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::OnceCell;

type Answer = Result<(Vec<IpAddr>, u32), String>;

pub struct ModemDns {
    cache: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
    inflight: Mutex<HashMap<String, Arc<OnceCell<Answer>>>>,
}

impl ModemDns {
    pub fn new() -> Self {
        ModemDns { cache: Mutex::new(HashMap::new()), inflight: Mutex::new(HashMap::new()) }
    }

    pub fn clear(&self) {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    pub fn gc(&self) {
        let now = Instant::now();
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, v| v.1 > now);
    }

    pub fn cached_entries(&self) -> usize {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// A records of `host` as answered by `server` (the modem unless router_dns says otherwise).
    pub async fn resolve(&self, nic: &NicInfo, server: Ipv4Addr, host: &str) -> Result<Vec<IpAddr>, String> {
        let key = host.to_ascii_lowercase();
        {
            let c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((ips, exp)) = c.get(&key) {
                if *exp > Instant::now() {
                    return Ok(ips.clone());
                }
            }
        }
        let cell = {
            let mut m = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            m.entry(key.clone()).or_insert_with(|| Arc::new(OnceCell::new())).clone()
        };
        let answer: Answer = cell.get_or_init(|| query_modem(nic, server, &key)).await.clone();
        self.inflight.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
        let (ips, ttl) = answer?;
        let life = Duration::from_secs(u64::from(ttl).clamp(20, 600));
        {
            let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if c.len() > 8192 {
                c.clear();
            }
            c.insert(key, (ips.clone(), Instant::now() + life));
        }
        if ips.is_empty() {
            Err(format!("the modem DNS ({}) has no A record for {}", server, host))
        } else {
            Ok(ips)
        }
    }
}

pub fn dns_build(name: &str, qid: u16) -> Result<Vec<u8>, String> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&qid.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, 1 question
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("'{}' is not a valid host name", name));
        }
        if !label.is_ascii() {
            return Err(format!("'{}' has non-ASCII characters (IDN names must be written in punycode)", name));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    Ok(q)
}

fn skip_name(buf: &[u8], mut p: usize) -> Option<usize> {
    loop {
        let len = *buf.get(p)? as usize;
        if len == 0 {
            return Some(p + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(p + 2);
        }
        p += 1 + len;
    }
}

/// `None` = not the answer to our query; `Some((ips, ttl))` otherwise (empty = NXDOMAIN/no data).
pub fn dns_parse(buf: &[u8], qid: u16) -> Option<(Vec<IpAddr>, u32)> {
    if buf.len() < 12 || u16::from_be_bytes([buf[0], buf[1]]) != qid {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        return None; // a query, not a response
    }
    if flags & 0x000F != 0 {
        return Some((Vec::new(), 30)); // error code (NXDOMAIN, SERVFAIL ...)
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut p = 12;
    for _ in 0..qd {
        p = skip_name(buf, p)? + 4;
    }
    let mut ips = Vec::new();
    let mut ttl_min = 600u32;
    for _ in 0..an {
        p = skip_name(buf, p)?;
        if p + 10 > buf.len() {
            break;
        }
        let t = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let ttl = u32::from_be_bytes([buf[p + 4], buf[p + 5], buf[p + 6], buf[p + 7]]);
        let rl = u16::from_be_bytes([buf[p + 8], buf[p + 9]]) as usize;
        p += 10;
        if p + rl > buf.len() {
            break;
        }
        if t == 1 && rl == 4 {
            ips.push(IpAddr::V4(Ipv4Addr::new(buf[p], buf[p + 1], buf[p + 2], buf[p + 3])));
            ttl_min = ttl_min.min(ttl);
        }
        p += rl;
    }
    Some((ips, ttl_min))
}

async fn query_modem(nic: &NicInfo, server: Ipv4Addr, host: &str) -> Answer {
    let qid = random_u16();
    let pkt = dns_build(host, qid)?;
    let sock: UdpSocket = net::bind_udp_on_nic(nic)
        .map_err(|e| format!("cannot open a DNS socket on the modem card: {}", e))?;
    let dest = SocketAddr::new(IpAddr::V4(server), 53);
    let mut buf = [0u8; 1500];
    for wait_ms in [600u64, 1000] {
        sock.send_to(&pkt, dest)
            .await
            .map_err(|e| format!("sending the DNS query to {} failed: {}", server, e))?;
        let deadline = Instant::now() + Duration::from_millis(wait_ms);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) => {
                    if from.ip() != IpAddr::V4(server) {
                        continue;
                    }
                    if let Some(ans) = dns_parse(&buf[..n], qid) {
                        return Ok(ans);
                    }
                }
                // Windows reports an earlier ICMP "port unreachable" as ConnectionReset on recv; ignore and keep waiting
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                Ok(Err(e)) => return Err(format!("receiving the DNS answer failed: {}", e)),
                Err(_) => break,
            }
        }
    }
    Err(format!("the modem DNS {} did not answer for {}", server, host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse() {
        let q = dns_build("digikala.com", 0x1234).unwrap();
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(*q.last().unwrap(), 1);
        // hand-made response: question echoed, CNAME (compressed) then one A record
        let mut r = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        r.extend_from_slice(&q[12..]);
        r.extend_from_slice(&[0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 0x0C]);
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 5, 200, 9, 9]);
        let (ips, ttl) = dns_parse(&r, 0x1234).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(5, 200, 9, 9))]);
        assert_eq!(ttl, 300);
        assert!(dns_parse(&r, 0x9999).is_none());
        let mut nx = r.clone();
        nx[3] = 0x83;
        assert!(dns_parse(&nx, 0x1234).unwrap().0.is_empty());
        assert!(dns_parse(&r[..10], 0x1234).is_none());
    }

    #[test]
    fn bad_names_are_rejected() {
        assert!(dns_build("a..b", 1).is_err());
        assert!(dns_build("пример.рф", 1).is_err());
        assert!(dns_build(&"a".repeat(64), 1).is_err());
    }
}
