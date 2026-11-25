//! Listener, per-connection routing, outbound connections and the TCP relay.
use crate::config::Settings;
use crate::net::{self, NicInfo};
use crate::rules::{self, Decision, Route};
use crate::state::{flags_of, Shared};
use crate::upstream;
use crate::util::{fmt_host_port, is_benign, is_loopback_ip, is_loopback_name, normalize_host};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

// ------------------------------------------------------------------ targets and errors

#[derive(Clone, Debug)]
pub enum Host {
    Name(String),
    Ip(IpAddr),
}

#[derive(Clone, Debug)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl Target {
    pub fn new(host: &str, port: u16) -> Target {
        let h = host.trim().trim_start_matches('[').trim_end_matches(']');
        match h.parse::<IpAddr>() {
            Ok(ip) => Target { host: Host::Ip(ip), port },
            Err(_) => Target { host: Host::Name(normalize_host(h)), port },
        }
    }
    pub fn host_string(&self) -> String {
        match &self.host {
            Host::Name(n) => n.clone(),
            Host::Ip(ip) => ip.to_string(),
        }
    }
    pub fn display(&self) -> String {
        fmt_host_port(&self.host_string(), self.port)
    }
    pub fn is_loopback(&self) -> bool {
        match &self.host {
            Host::Name(n) => is_loopback_name(n),
            Host::Ip(ip) => is_loopback_ip(*ip),
        }
    }
}

#[derive(Debug)]
pub enum ConnectError {
    Blocked(String),
    Refused(String),
    Timeout(String),
    Dns(String),
    Other(String),
}

impl ConnectError {
    pub fn from_io(e: io::Error) -> ConnectError {
        match e.kind() {
            io::ErrorKind::ConnectionRefused => ConnectError::Refused(e.to_string()),
            io::ErrorKind::TimedOut => ConnectError::Timeout(e.to_string()),
            _ => ConnectError::Other(e.to_string()),
        }
    }
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Blocked(s) => write!(f, "blocked: {}", s),
            ConnectError::Refused(s) => write!(f, "connection refused: {}", s),
            ConnectError::Timeout(s) => write!(f, "timed out: {}", s),
            ConnectError::Dns(s) => write!(f, "DNS: {}", s),
            ConnectError::Other(s) => write!(f, "{}", s),
        }
    }
}

// ------------------------------------------------------------------ decisions and exits

pub fn decide(st: &Shared, t: &Target) -> Decision {
    let dv = st.diverts.load_full();
    match &t.host {
        Host::Ip(ip) => {
            let ir = st.ir.load_full();
            rules::decide_ip(*ip, &dv, &ir)
        }
        Host::Name(n) => {
            let lists = st.lists.load_full();
            let s = st.settings.load_full();
            rules::decide_host(n, &lists, &dv, &flags_of(&s))
        }
    }
}

pub fn dns_server(s: &Settings, nic: &NicInfo) -> Option<Ipv4Addr> {
    let t = s.router_dns.trim();
    if !t.is_empty() && !t.eq_ignore_ascii_case("auto") {
        t.parse().ok()
    } else {
        nic.gateway
    }
}

pub fn no_nic_error() -> ConnectError {
    ConnectError::Other("the real network card was not found; press Refresh in the UI or set nic_ip in Settings".into())
}

/// Straight out of the modem. Names are resolved by the modem's DNS first.
pub async fn connect_router(st: &Shared, t: &Target) -> Result<TcpStream, ConnectError> {
    let nic = st.nic.load_full().ok_or_else(no_nic_error)?;
    match &t.host {
        Host::Ip(ip) => net::connect_tcp_on_nic(&nic, *ip, t.port).await.map_err(ConnectError::from_io),
        Host::Name(name) => {
            let s = st.settings.load_full();
            let server = dns_server(&s, &nic).ok_or_else(|| {
                ConnectError::Dns("the modem address is unknown, so its DNS cannot be asked (set router_ip or router_dns)".into())
            })?;
            let ips = st.dns.resolve(&nic, server, name).await.map_err(ConnectError::Dns)?;
            let mut last = ConnectError::Other("no address to try".into());
            for ip in ips.into_iter().take(4) {
                match net::connect_tcp_on_nic(&nic, ip, t.port).await {
                    Ok(s) => return Ok(s),
                    Err(e) => last = ConnectError::from_io(e),
                }
            }
            Err(last)
        }
    }
}

/// Through "ip net": the Windows system proxy / manual upstream, or the normal route of a system-wide VPN.
pub async fn connect_vpn_target(st: &Shared, t: &Target) -> Result<TcpStream, ConnectError> {
    let resolver = st.upstream.load_full();
    let up = resolver.current().await;
    upstream::connect_vpn(up.as_ref(), &t.host_string(), t.port)
        .await
        .map_err(ConnectError::from_io)
}

pub struct Opened {
    pub stream: TcpStream,
    pub route: Route,
}

fn count_route(st: &Shared, r: Route) {
    match r {
        Route::Router => st.stats.router.fetch_add(1, Ordering::Relaxed),
        Route::Vpn => st.stats.vpn.fetch_add(1, Ordering::Relaxed),
        Route::Block => st.stats.blocked.fetch_add(1, Ordering::Relaxed),
    };
}

/// Decide the route for `t` and open the outgoing connection. Logs the decision and every failure.
pub async fn open_outbound(st: &Arc<Shared>, peer: SocketAddr, kind: &str, t: &Target) -> Result<Opened, ConnectError> {
    if t.is_loopback() {
        count_route(st, Route::Block);
        log_warn!("[{}] {} {} => BLOCK (loopback destinations are not allowed)", peer, kind, t.display());
        return Err(ConnectError::Blocked("loopback destinations are not allowed".into()));
    }
    let d = decide(st, t);
    if st.settings.load_full().log_connections {
        log_info!("[{}] {} {} => {} ({})", peer, kind, t.display(), d.route.as_str(), d.reason);
    }
    let res = match d.route {
        Route::Block => {
            count_route(st, Route::Block);
            return Err(ConnectError::Blocked(format!("blocked by {}", d.reason)));
        }
        Route::Router => connect_router(st, t).await,
        Route::Vpn => connect_vpn_target(st, t).await,
    };
    match res {
        Ok(stream) => {
            count_route(st, d.route);
            Ok(Opened { stream, route: d.route })
        }
        Err(e) => {
            st.stats.failed.fetch_add(1, Ordering::Relaxed);
            log_warn!("[{}] {} {} => {} ({}) FAILED: {}", peer, kind, t.display(), d.route.as_str(), d.reason, e);
            Err(e)
        }
    }
}

// ------------------------------------------------------------------ SNI sniffing for bare IPs

/// Server name from a TLS ClientHello (no DNS needed), or None.
pub fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 48 || data[0] != 0x16 || data[5] != 0x01 {
        return None;
    }
    let mut p = 5 + 4 + 2 + 32;
    p += 1 + *data.get(p)? as usize; // session id
    let cs = u16::from_be_bytes([*data.get(p)?, *data.get(p + 1)?]) as usize;
    p += 2 + cs; // cipher suites
    p += 1 + *data.get(p)? as usize; // compression methods
    let ext_len = u16::from_be_bytes([*data.get(p)?, *data.get(p + 1)?]) as usize;
    p += 2;
    let end = (p + ext_len).min(data.len());
    while p + 4 <= end {
        let et = u16::from_be_bytes([data[p], data[p + 1]]);
        let el = u16::from_be_bytes([data[p + 2], data[p + 3]]) as usize;
        p += 4;
        if et == 0 {
            let nl = u16::from_be_bytes([*data.get(p + 3)?, *data.get(p + 4)?]) as usize;
            let name = data.get(p + 5..p + 5 + nl)?;
            let s = String::from_utf8_lossy(name).to_ascii_lowercase();
            return if s.is_empty() { None } else { Some(s) };
        }
        p += el;
    }
    None
}

/// Worth sniffing: TLS port, destination is a bare IP, and the IP rules have no opinion.
pub fn should_sniff(st: &Shared, t: &Target) -> bool {
    if !matches!(t.host, Host::Ip(_)) || !(t.port == 443 || t.port == 8443) || t.is_loopback() {
        return false;
    }
    if !st.settings.load_full().sniff_sni {
        return false;
    }
    decide(st, t).reason == "default"
}

/// TLS to a bare IP: the VPN connection starts at once (so a normal foreign site loses no time),
/// meanwhile the client's first bytes are read to learn the server name. If the name says
/// Iranian/ads/forced, the speculative connection is dropped and the right exit is used.
/// Returns the connected remote side plus the bytes already read from the client.
/// `Ok(None)` = the client went away.
pub async fn sniff_connect(
    st: &Arc<Shared>,
    client: &mut TcpStream,
    peer: SocketAddr,
    kind: &str,
    t: &Target,
    ok_reply: &[u8],
) -> Result<Option<(TcpStream, Vec<u8>, Route)>, ConnectError> {
    let (st2, t2) = (st.clone(), t.clone());
    let spec: JoinHandle<Result<TcpStream, ConnectError>> =
        tokio::spawn(async move { connect_vpn_target(&st2, &t2).await });
    if let Err(e) = client.write_all(ok_reply).await {
        spec.abort();
        return Err(ConnectError::from_io(e));
    }
    if let Err(e) = client.flush().await {
        spec.abort();
        return Err(ConnectError::from_io(e));
    }
    let mut buf = vec![0u8; 4096];
    let (n, timed_out) = match tokio::time::timeout(Duration::from_millis(300), client.read(&mut buf)).await {
        Ok(Ok(n)) => (n, false),
        Ok(Err(e)) => {
            spec.abort();
            return Err(ConnectError::from_io(e));
        }
        Err(_) => (0, true),
    };
    if n == 0 && !timed_out {
        spec.abort();
        return Ok(None);
    }
    buf.truncate(n);
    let first = buf;
    let sni = parse_sni(&first);
    let mut d = Decision { route: Route::Vpn, reason: "default" };
    if let Some(name) = &sni {
        d = decide(st, &Target::new(name, t.port));
    }
    if st.settings.load_full().log_connections {
        log_info!(
            "[{}] {} {} => {} ({}; SNI {})",
            peer, kind, t.display(), d.route.as_str(), d.reason, sni.as_deref().unwrap_or("none")
        );
    }
    match d.route {
        Route::Block => {
            spec.abort();
            count_route(st, Route::Block);
            Err(ConnectError::Blocked(format!("blocked by {}", d.reason)))
        }
        Route::Router => {
            spec.abort();
            match connect_router(st, t).await {
                Ok(s) => {
                    count_route(st, Route::Router);
                    Ok(Some((s, first, Route::Router)))
                }
                Err(e) => {
                    st.stats.failed.fetch_add(1, Ordering::Relaxed);
                    log_warn!("[{}] {} {} => ROUTER FAILED: {}", peer, kind, t.display(), e);
                    Err(e)
                }
            }
        }
        Route::Vpn => match spec.await {
            Ok(Ok(s)) => {
                count_route(st, Route::Vpn);
                Ok(Some((s, first, Route::Vpn)))
            }
            Ok(Err(e)) => {
                st.stats.failed.fetch_add(1, Ordering::Relaxed);
                log_warn!("[{}] {} {} => VPN FAILED: {}", peer, kind, t.display(), e);
                Err(e)
            }
            Err(e) => Err(ConnectError::Other(format!("connect task failed: {}", e))),
        },
    }
}

// ------------------------------------------------------------------ relay

pub struct Flow<'a> {
    pub peer: SocketAddr,
    pub kind: &'a str,
    pub target: String,
    pub route: Route,
}

struct Tracked<'a, S> {
    inner: &'a mut S,
    last: Arc<AtomicU64>,
    base: Instant,
}

impl<'a, S> Tracked<'a, S> {
    fn touch(&self) {
        self.last.store(self.base.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}

impl<'a, S: AsyncRead + Unpin> AsyncRead for Tracked<'a, S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            if buf.filled().len() > before {
                self.touch();
            }
        }
        r
    }
}

impl<'a, S: AsyncWrite + Unpin> AsyncWrite for Tracked<'a, S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut *self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &r {
            if *n > 0 {
                self.touch();
            }
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

async fn idle_watch(last: Arc<AtomicU64>, base: Instant, idle: Duration) {
    let idle_ms = idle.as_millis() as u64;
    loop {
        let seen = last.load(Ordering::Relaxed);
        let now = base.elapsed().as_millis() as u64;
        let quiet = now.saturating_sub(seen);
        if quiet >= idle_ms {
            return;
        }
        let wait = (idle_ms - quiet).clamp(250, 30_000);
        tokio::time::sleep(Duration::from_millis(wait)).await;
    }
}

pub fn log_flow_error(f: &Flow<'_>, what: &str, e: &io::Error) {
    if is_benign(e) {
        return;
    }
    log_warn!("[{}] {} {} => {}: {} failed: {}", f.peer, f.kind, f.target, f.route.as_str(), what, e);
}

/// Copy both directions until both sides are done. When one side errors both sockets are closed;
/// when one side finishes, the other gets its FIN (half-close) and a connection that then stays
/// silent is cut by the idle timeout, so half-open sockets cannot pile up.
pub async fn relay(st: &Shared, client: &mut TcpStream, remote: &mut TcpStream, first: &[u8], flow: &Flow<'_>) {
    if !first.is_empty() {
        if let Err(e) = remote.write_all(first).await {
            log_flow_error(flow, "sending the first bytes", &e);
            let _ = client.shutdown().await;
            return;
        }
        st.stats.up.fetch_add(first.len() as u64, Ordering::Relaxed);
    }
    let idle = Duration::from_secs(st.settings.load_full().idle_timeout_secs);
    let base = Instant::now();
    let last = Arc::new(AtomicU64::new(0));
    let outcome: io::Result<Option<(u64, u64)>> = {
        let mut a = Tracked { inner: &mut *client, last: last.clone(), base };
        let mut b = Tracked { inner: &mut *remote, last: last.clone(), base };
        tokio::select! {
            r = copy_bidirectional(&mut a, &mut b) => r.map(Some),
            _ = idle_watch(last.clone(), base, idle) => Ok(None),
        }
    };
    match outcome {
        Ok(Some((up, down))) => {
            st.stats.up.fetch_add(up, Ordering::Relaxed);
            st.stats.down.fetch_add(down, Ordering::Relaxed);
        }
        Ok(None) => {
            log_info!("[{}] {} {} => {}: closed after {} s without traffic", flow.peer, flow.kind, flow.target, flow.route.as_str(), idle.as_secs());
        }
        Err(e) => log_flow_error(flow, "relaying", &e),
    }
    let _ = client.shutdown().await;
    let _ = remote.shutdown().await;
}

// ------------------------------------------------------------------ listener

pub struct ProxyHandle {
    stop: watch::Sender<bool>,
    join: JoinHandle<()>,
    pub addr: SocketAddr,
}

pub async fn is_running(st: &Arc<Shared>) -> Option<SocketAddr> {
    st.proxy.lock().await.as_ref().map(|h| h.addr)
}

pub async fn start(st: &Arc<Shared>) -> Result<SocketAddr, String> {
    let mut guard = st.proxy.lock().await;
    if let Some(h) = guard.as_ref() {
        return Ok(h.addr);
    }
    let s = st.settings.load_full();
    let ip: IpAddr = if s.listen_host.trim().eq_ignore_ascii_case("auto") {
        match st.nic.load_full() {
            Some(n) => IpAddr::V4(n.ip),
            None => {
                log_warn!("the real network card is unknown, listening on all addresses (0.0.0.0)");
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            }
        }
    } else {
        s.listen_host.trim().parse().map_err(|e| format!("bad listen address '{}': {}", s.listen_host, e))?
    };
    let listener = TcpListener::bind(SocketAddr::new(ip, s.port))
        .await
        .map_err(|e| format!("cannot listen on {}: {}", fmt_host_port(&ip.to_string(), s.port), e))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let port = s.port;
    let fw = tokio::task::spawn_blocking(move || net::add_firewall_rules(port)).await.unwrap_or(false);
    if !fw {
        log_warn!("could not add the Windows Firewall rule (run as Administrator, or allow the program when Windows asks)");
    }
    let (tx, rx) = watch::channel(false);
    let join = tokio::spawn(accept_loop(st.clone(), listener, rx));
    *guard = Some(ProxyHandle { stop: tx, join, addr });
    log_info!("proxy listening on {} (SOCKS5 and HTTP on the same port)", addr);
    Ok(addr)
}

pub async fn stop(st: &Arc<Shared>) {
    let handle = st.proxy.lock().await.take();
    if let Some(h) = handle {
        let _ = h.stop.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), h.join).await;
        log_info!("proxy stopped");
    }
}

async fn wait_stop(mut rx: watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

async fn accept_loop(st: Arc<Shared>, listener: TcpListener, mut stop_rx: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            res = listener.accept() => match res {
                Ok((sock, peer)) => {
                    let st2 = st.clone();
                    let rx = stop_rx.clone();
                    tokio::spawn(async move {
                        st2.stats.active.fetch_add(1, Ordering::Relaxed);
                        st2.stats.total.fetch_add(1, Ordering::Relaxed);
                        tokio::select! {
                            _ = handle_client(&st2, sock, peer) => {}
                            _ = wait_stop(rx) => {}
                        }
                        st2.stats.active.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(e) => {
                    log_err!("accepting a connection failed: {}", e);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            },
            _ = stop_rx.changed() => {}
        }
        if *stop_rx.borrow() {
            break;
        }
    }
}

async fn handle_client(st: &Arc<Shared>, sock: TcpStream, peer: SocketAddr) {
    let _ = sock.set_nodelay(true);
    let mut first = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(30), sock.peek(&mut first)).await {
        Ok(Ok(0)) => return,
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            if !is_benign(&e) {
                log_warn!("[{}] reading the first byte failed: {}", peer, e);
            }
            return;
        }
        Err(_) => {
            log_warn!("[{}] the client connected but sent nothing for 30 s; closing", peer);
            return;
        }
    }
    if first[0] == 5 {
        crate::socks::handle(st, sock, peer).await;
    } else {
        crate::httpx::handle(st, sock, peer).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parsing() {
        assert!(matches!(Target::new("[::1]", 80).host, Host::Ip(_)));
        assert!(matches!(Target::new("Example.COM.", 80).host, Host::Name(ref n) if n == "example.com"));
        assert!(Target::new("127.0.0.1", 1).is_loopback());
        assert!(Target::new("LOCALHOST", 1).is_loopback());
        assert!(!Target::new("192.168.1.1", 1).is_loopback());
        assert_eq!(Target::new("::1", 443).display(), "[::1]:443");
    }

    #[test]
    fn sni_from_a_hand_built_client_hello() {
        let name = b"digikala.com";
        let mut sni_ext = vec![0, 0];
        let list_len = (name.len() + 3) as u16;
        sni_ext.extend_from_slice(&(list_len + 2).to_be_bytes());
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session id len
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[1, 0]); // compression
        body.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&sni_ext);
        let mut hs = vec![1];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        assert_eq!(parse_sni(&rec).as_deref(), Some("digikala.com"));
        assert_eq!(parse_sni(&rec[..40]), None);
        assert_eq!(parse_sni(b"GET / HTTP/1.1\r\n\r\n padding padding padding padding"), None);
    }
}
