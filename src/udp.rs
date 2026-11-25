//! SOCKS5 UDP ASSOCIATE (DNS, QUIC/HTTP3, voice). Every datagram follows the same routing rules
//! as TCP: ROUTER datagrams leave through a socket locked to the modem card; VPN datagrams use
//! the normal route (system-wide VPN) or, when the upstream is a SOCKS5 proxy, its UDP relay.
//! A VPN route that cannot carry UDP (HTTP-only upstream) drops the datagram *with a log line*;
//! QUIC (udp/443) is called out so the browser falls back to TCP.
use crate::net::{self, NicInfo};
use crate::proxy::{self, Host, Target};
use crate::rules::Route;
use crate::state::Shared;
use crate::upstream::{self, UpKind, UpstreamSpec};
use crate::util::invalid;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const UDP_IDLE: Duration = Duration::from_secs(180);

/// UDP relay of an upstream SOCKS5 proxy (kept alive by its TCP control connection).
struct SocksUdp {
    _ctrl: TcpStream,
    sock: UdpSocket,
}

enum VpnUdp {
    None,
    Plain(UdpSocket),
    Socks(SocksUdp),
}

impl VpnUdp {
    /// (bytes, sender). A plain socket reports who answered; an upstream SOCKS5 relay already
    /// wraps the datagram in a SOCKS5 header, so there is no separate sender.
    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
        match self {
            VpnUdp::Plain(s) => s.recv_from(buf).await.map(|(n, from)| (n, Some(from))),
            VpnUdp::Socks(u) => u.sock.recv(buf).await.map(|n| (n, None)),
            VpnUdp::None => std::future::pending().await,
        }
    }
}

async fn recv_opt(s: &Option<UdpSocket>, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    match s {
        Some(s) => s.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

async fn socks_udp_upstream(spec: &UpstreamSpec) -> io::Result<SocksUdp> {
    let mut ctrl = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((spec.host.as_str(), spec.port)))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the upstream SOCKS5 proxy did not answer"))??;
    upstream::socks5_handshake(&mut ctrl, spec).await?;
    ctrl.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?; // UDP ASSOCIATE 0.0.0.0:0
    let mut head = [0u8; 4];
    ctrl.read_exact(&mut head).await?;
    if head[0] != 5 || head[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("the upstream SOCKS5 proxy refused UDP ASSOCIATE (code {})", head[1]),
        ));
    }
    let relay_ip: IpAddr = match head[3] {
        1 => {
            let mut a = [0u8; 4];
            ctrl.read_exact(&mut a).await?;
            IpAddr::from(a)
        }
        4 => {
            let mut a = [0u8; 16];
            ctrl.read_exact(&mut a).await?;
            IpAddr::from(a)
        }
        other => return Err(invalid(format!("unsupported relay address type {} from the upstream", other))),
    };
    let mut p = [0u8; 2];
    ctrl.read_exact(&mut p).await?;
    let relay_port = u16::from_be_bytes(p);
    // a proxy that answers 0.0.0.0 means "the address you reached me on"
    let relay_ip = if relay_ip.is_unspecified() {
        ctrl.peer_addr()?.ip()
    } else {
        relay_ip
    };
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(SocketAddr::new(relay_ip, relay_port)).await?;
    Ok(SocksUdp { _ctrl: ctrl, sock })
}

fn bound_reply(addr: SocketAddr) -> Vec<u8> {
    let mut r = vec![5u8, 0, 0];
    match addr.ip() {
        IpAddr::V4(a) => {
            r.push(1);
            r.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            r.push(4);
            r.extend_from_slice(&a.octets());
        }
    }
    r.extend_from_slice(&addr.port().to_be_bytes());
    r
}

fn wrap_reply(from: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8, 0, 0];
    match from.ip() {
        IpAddr::V4(a) => {
            out.push(1);
            out.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            out.push(4);
            out.extend_from_slice(&a.octets());
        }
    }
    out.extend_from_slice(&from.port().to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// (host, port, payload offset) of a SOCKS5 UDP datagram, or None when it is malformed / fragmented.
pub fn parse_udp_header(d: &[u8]) -> Option<(String, u16, usize)> {
    if d.len() < 10 || d[2] != 0 {
        return None;
    }
    let (host, off) = match d[3] {
        1 => (std::net::Ipv4Addr::new(d[4], d[5], d[6], d[7]).to_string(), 8),
        3 => {
            let l = d[4] as usize;
            let name = d.get(5..5 + l)?;
            (String::from_utf8_lossy(name).into_owned(), 5 + l)
        }
        4 => {
            let b: [u8; 16] = d.get(4..20)?.try_into().ok()?;
            (std::net::Ipv6Addr::from(b).to_string(), 20)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*d.get(off)?, *d.get(off + 1)?]);
    Some((host, port, off + 2))
}

struct Ctx<'a> {
    st: &'a Arc<Shared>,
    nic: &'a Option<Arc<NicInfo>>,
    router: &'a Option<UdpSocket>,
    vpn: &'a VpnUdp,
    client_ip: IpAddr,
}

/// Log a message the first time it is seen (UDP can be chatty), bounded memory.
fn log_once(seen: &mut HashSet<String>, msg: String) {
    if seen.len() > 512 {
        seen.clear();
    }
    if seen.insert(msg.clone()) {
        log_warn!("{}", msg);
    }
}

async fn send_datagram(
    cx: &Ctx<'_>,
    data: &[u8],
    sent: &mut HashSet<(IpAddr, u16)>,
    seen: &mut HashSet<String>,
    seen_info: &mut HashSet<String>,
) {
    let (host, port, off) = match parse_udp_header(data) {
        Some(x) => x,
        None => {
            log_once(seen, format!("[{}] UDP: a malformed or fragmented datagram was dropped (fragmentation is not supported)", cx.client_ip));
            return;
        }
    };
    let payload = &data[off..];
    let t = Target::new(&host, port);
    if t.is_loopback() {
        log_once(seen, format!("[{}] UDP -> {} blocked: loopback destinations are not allowed", cx.client_ip, t.display()));
        return;
    }
    let d = proxy::decide(cx.st, &t);
    if cx.st.settings.load_full().log_connections {
        let line = format!("[{}] UDP {} => {} ({})", cx.client_ip, t.display(), d.route.as_str(), d.reason);
        if seen_info.len() > 512 {
            seen_info.clear();
        }
        if seen_info.insert(line.clone()) {
            log_info!("{}", line);
        }
    }
    match d.route {
        Route::Block => {}
        Route::Router => {
            let sock = match cx.router {
                Some(s) => s,
                None => {
                    log_once(seen, format!("[{}] UDP -> {} could not use the modem: no socket on the real network card", cx.client_ip, t.display()));
                    return;
                }
            };
            let nic = match cx.nic {
                Some(n) => n,
                None => return,
            };
            let ip = match &t.host {
                Host::Ip(ip) => *ip,
                Host::Name(n) => {
                    let s = cx.st.settings.load_full();
                    let server = match proxy::dns_server(&s, nic) {
                        Some(x) => x,
                        None => {
                            log_once(seen, format!("[{}] UDP -> {}: the modem address is unknown, cannot resolve the name", cx.client_ip, n));
                            return;
                        }
                    };
                    match cx.st.dns.resolve(nic, server, n).await {
                        Ok(ips) => ips[0],
                        Err(e) => {
                            log_once(seen, format!("[{}] UDP -> {}: {}", cx.client_ip, n, e));
                            return;
                        }
                    }
                }
            };
            sent.insert((ip, port));
            let mut res = sock.send_to(payload, SocketAddr::new(ip, port)).await;
            let unreachable = matches!(&res, Err(e) if net::is_unreachable(e));
            if unreachable {
                if let IpAddr::V4(v4) = ip {
                    match net::ensure_host_route(nic, v4).await {
                        Ok(()) => res = sock.send_to(payload, SocketAddr::new(ip, port)).await,
                        Err(m) => log_once(
                            seen,
                            format!("[{}] UDP -> {}: no route through the modem and adding one failed: {}", cx.client_ip, t.display(), m),
                        ),
                    }
                }
            }
            if let Err(e) = res {
                log_once(seen, format!("[{}] UDP -> {} through the modem failed: {}", cx.client_ip, t.display(), e));
            }
        }
        Route::Vpn => match cx.vpn {
            VpnUdp::Plain(sock) => {
                let ip = match &t.host {
                    Host::Ip(ip) => *ip,
                    Host::Name(n) => match tokio::net::lookup_host((n.as_str(), port)).await {
                        Ok(mut it) => match it.find(|a| a.is_ipv4()) {
                            Some(a) => a.ip(),
                            None => {
                                log_once(seen, format!("[{}] UDP -> {}: no IPv4 address", cx.client_ip, n));
                                return;
                            }
                        },
                        Err(e) => {
                            log_once(seen, format!("[{}] UDP -> {}: name lookup failed: {}", cx.client_ip, n, e));
                            return;
                        }
                    },
                };
                sent.insert((ip, port));
                if let Err(e) = sock.send_to(payload, SocketAddr::new(ip, port)).await {
                    log_once(seen, format!("[{}] UDP -> {} through the VPN failed: {}", cx.client_ip, t.display(), e));
                }
            }
            VpnUdp::Socks(u) => {
                // the datagram already carries the SOCKS5 UDP header: hand it to the upstream relay as is
                if let Err(e) = u.sock.send(data).await {
                    log_once(seen, format!("[{}] UDP -> {} via the upstream SOCKS5 relay failed: {}", cx.client_ip, t.display(), e));
                }
            }
            VpnUdp::None => {
                let extra = if port == 443 {
                    " (QUIC/HTTP3: the browser will fall back to TCP)"
                } else {
                    ""
                };
                log_once(
                    seen,
                    format!(
                        "[{}] UDP -> {} dropped: the VPN route has no UDP path (an HTTP-only upstream cannot carry UDP){}",
                        cx.client_ip,
                        t.display(),
                        extra
                    ),
                );
            }
        },
    }
}

pub async fn associate(st: &Arc<Shared>, ctrl: &mut TcpStream, peer: SocketAddr) -> io::Result<()> {
    let local_ip = ctrl.local_addr()?.ip();
    let client_ip = peer.ip();
    let nic = st.nic.load_full();

    let client_sock = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
    let bnd = client_sock.local_addr()?;

    let router: Option<UdpSocket> = match &nic {
        Some(n) => match net::bind_udp_on_nic(n) {
            Ok(s) => Some(s),
            Err(e) => {
                log_warn!("[{}] UDP via the modem is unavailable: {}", peer, e);
                None
            }
        },
        None => {
            log_warn!("[{}] UDP via the modem is unavailable: the real network card was not found", peer);
            None
        }
    };

    let resolver = st.upstream.load_full();
    let up = resolver.current().await;
    let vpn = match &up {
        None => match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => VpnUdp::Plain(s),
            Err(e) => {
                log_warn!("[{}] UDP via the VPN is unavailable: {}", peer, e);
                VpnUdp::None
            }
        },
        Some(spec) if spec.kind == UpKind::Socks5 => match socks_udp_upstream(spec).await {
            Ok(u) => VpnUdp::Socks(u),
            Err(e) => {
                log_warn!("[{}] UDP via the upstream SOCKS5 proxy {} is unavailable: {}", peer, spec.describe(), e);
                VpnUdp::None
            }
        },
        Some(spec) => {
            log_warn!(
                "[{}] the upstream {} is an HTTP proxy: UDP/QUIC cannot go through it (only UDP routed to the modem works)",
                peer,
                spec.describe()
            );
            VpnUdp::None
        }
    };

    ctrl.write_all(&bound_reply(bnd)).await?;
    ctrl.flush().await?;
    log_info!("[{}] UDP ASSOCIATE ready on {}", peer, bnd);

    let cx = Ctx { st, nic: &nic, router: &router, vpn: &vpn, client_ip };
    let mut cbuf = vec![0u8; 65535];
    let mut rbuf = vec![0u8; 65535];
    let mut vbuf = vec![0u8; 65535];
    let mut tmp = [0u8; 64];
    let mut client_addr: Option<SocketAddr> = None;
    let mut sent: HashSet<(IpAddr, u16)> = HashSet::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut seen_info: HashSet<String> = HashSet::new();

    loop {
        tokio::select! {
            r = client_sock.recv_from(&mut cbuf) => {
                let (n, from) = match r {
                    Ok(v) => v,
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                    Err(e) => return Err(e),
                };
                if from.ip() != client_ip {
                    log_once(&mut seen, format!("[{}] UDP: a datagram from {} (not the client) was ignored", peer, from.ip()));
                    continue;
                }
                client_addr = Some(from);
                send_datagram(&cx, &cbuf[..n], &mut sent, &mut seen, &mut seen_info).await;
            }
            r = recv_opt(&router, &mut rbuf) => {
                let (n, from) = match r {
                    Ok(v) => v,
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                    Err(e) => return Err(e),
                };
                if let Some(ca) = client_addr {
                    if sent.contains(&(from.ip(), from.port())) {
                        let _ = client_sock.send_to(&wrap_reply(from, &rbuf[..n]), ca).await;
                    }
                }
            }
            r = vpn.recv(&mut vbuf) => {
                let (n, from) = match r {
                    Ok(v) => v,
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                    Err(e) => return Err(e),
                };
                if let Some(ca) = client_addr {
                    match from {
                        Some(f) => {
                            if sent.contains(&(f.ip(), f.port())) {
                                let _ = client_sock.send_to(&wrap_reply(f, &vbuf[..n]), ca).await;
                            }
                        }
                        None => {
                            let _ = client_sock.send_to(&vbuf[..n], ca).await;
                        }
                    }
                }
            }
            r = ctrl.read(&mut tmp) => {
                match r {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            _ = tokio::time::sleep(UDP_IDLE) => {
                log_info!("[{}] UDP association closed after {} s without traffic", peer, UDP_IDLE.as_secs());
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_parsing() {
        let mut d = vec![0, 0, 0, 1, 8, 8, 8, 8, 0, 53];
        d.extend_from_slice(b"payload");
        assert_eq!(parse_udp_header(&d), Some(("8.8.8.8".to_string(), 53, 10)));
        let mut d = vec![0, 0, 0, 3, 11];
        d.extend_from_slice(b"example.com");
        d.extend_from_slice(&[1, 187]);
        assert_eq!(parse_udp_header(&d), Some(("example.com".to_string(), 443, 18)));
        assert_eq!(parse_udp_header(&[0, 0, 1, 1, 8, 8, 8, 8, 0, 53]), None); // fragmented
        assert_eq!(parse_udp_header(&[0, 0, 0, 1, 8]), None);
    }

    #[test]
    fn reply_wrapping() {
        let from: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let w = wrap_reply(from, b"abc");
        assert_eq!(&w[..10], &[0, 0, 0, 1, 1, 2, 3, 4, 0, 53]);
        assert_eq!(&w[10..], b"abc");
    }
}
