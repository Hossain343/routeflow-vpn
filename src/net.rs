//! Windows networking glue: finding the real (physical) network card and the modem, sockets that
//! are forced out of that card even while a VPN owns the default route, firewall rules, browser.
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

#[derive(Clone, Debug)]
pub struct NicInfo {
    pub name: String,
    pub ip: Ipv4Addr,
    pub index: u32,
    pub gateway: Option<Ipv4Addr>,
}

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn hidden_command(program: &str) -> std::process::Command {
    let mut c = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c
}

// ------------------------------------------------------------------ pure parsers (unit-tested)

/// `route print -4` -> default gateway of the interface that owns `iface_ip` (lowest metric).
pub fn parse_route_print(text: &str, iface_ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let want = iface_ip.to_string();
    let mut best: Option<(u32, Ipv4Addr)> = None;
    for line in text.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() >= 5 && p[0] == "0.0.0.0" && p[1] == "0.0.0.0" && p[3] == want {
            if let Ok(gw) = p[2].parse::<Ipv4Addr>() {
                let metric = p[4].parse::<u32>().unwrap_or(9999);
                if best.map(|b| metric < b.0).unwrap_or(true) {
                    best = Some((metric, gw));
                }
            }
        }
    }
    best.map(|b| b.1)
}

/// Fallback when PowerShell is unavailable: lowest-metric default route that has a real gateway.
pub fn parse_route_print_any(text: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let mut best: Option<(u32, Ipv4Addr, Ipv4Addr)> = None;
    for line in text.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() >= 5 && p[0] == "0.0.0.0" && p[1] == "0.0.0.0" {
            if let (Ok(gw), Ok(ip)) = (p[2].parse::<Ipv4Addr>(), p[3].parse::<Ipv4Addr>()) {
                let metric = p[4].parse::<u32>().unwrap_or(9999);
                if best.map(|b| metric < b.0).unwrap_or(true) {
                    best = Some((metric, gw, ip));
                }
            }
        }
    }
    best.map(|b| (b.2, b.1))
}

/// Output of the PowerShell snippet (an object or an array of objects).
pub fn parse_nic_json(text: &str) -> Result<Vec<(u32, NicInfo)>, String> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(Vec::new());
    }
    let v: serde_json::Value = serde_json::from_str(t).map_err(|e| format!("bad adapter list: {}", e))?;
    let items: Vec<serde_json::Value> = match v {
        serde_json::Value::Array(a) => a,
        serde_json::Value::Null => Vec::new(),
        other => vec![other],
    };
    let mut out = Vec::new();
    for it in items {
        let name = it.get("name").and_then(|x| x.as_str()).unwrap_or("?").to_string();
        let index = it.get("index").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
        let ip = it.get("ip").and_then(|x| x.as_str()).and_then(|x| x.parse::<Ipv4Addr>().ok());
        let gw = it.get("gw").and_then(|x| x.as_str()).and_then(|x| x.parse::<Ipv4Addr>().ok());
        let metric = it.get("metric").and_then(|x| x.as_u64()).unwrap_or(9999) as u32;
        if let (Some(ip), true) = (ip, index != 0) {
            out.push((metric, NicInfo { name, ip, index, gateway: gw }));
        }
    }
    out.sort_by_key(|x| x.0);
    Ok(out)
}

// ------------------------------------------------------------------ Windows FFI

#[cfg(windows)]
mod ffi {
    #[link(name = "ws2_32")]
    extern "system" {
        pub fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
    }
    #[link(name = "iphlpapi")]
    extern "system" {
        pub fn GetIpAddrTable(table: *mut u8, size: *mut u32, order: i32) -> u32;
    }
}

/// Interface index of the adapter that owns this IPv4 address.
#[cfg(windows)]
pub fn ifindex_for_ip(ip: Ipv4Addr) -> Option<u32> {
    let mut size: u32 = 0;
    unsafe { ffi::GetIpAddrTable(std::ptr::null_mut(), &mut size, 0) };
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe { ffi::GetIpAddrTable(buf.as_mut_ptr(), &mut size, 0) };
    if rc != 0 || buf.len() < 4 {
        return None;
    }
    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let target = u32::from_le_bytes(ip.octets());
    for i in 0..n {
        // MIB_IPADDRROW is 24 bytes: addr, index, mask, bcast, reasm(+2 pad words)
        let off = 4 + i * 24;
        if off + 8 > buf.len() {
            break;
        }
        let addr = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        let idx = u32::from_le_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
        if addr == target {
            return Some(idx);
        }
    }
    None
}

#[cfg(not(windows))]
pub fn ifindex_for_ip(_ip: Ipv4Addr) -> Option<u32> {
    Some(1)
}

#[cfg(windows)]
fn set_unicast_if(raw: u64, v6: bool, index: u32) -> io::Result<()> {
    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;
    const IP_UNICAST_IF: i32 = 31;
    const IPV6_UNICAST_IF: i32 = 31;
    // IPv4 wants the index in network byte order, IPv6 in host order
    let (level, opt, val): (i32, i32, u32) = if v6 {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    } else {
        (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    };
    let rc = unsafe { ffi::setsockopt(raw as usize, level, opt, &val as *const u32 as *const u8, 4) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn force_tcp(sock: &TcpSocket, v6: bool, index: u32) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    set_unicast_if(sock.as_raw_socket(), v6, index)
}
#[cfg(not(windows))]
fn force_tcp(_sock: &TcpSocket, _v6: bool, _index: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn force_udp(sock: &std::net::UdpSocket, index: u32) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    set_unicast_if(sock.as_raw_socket(), false, index)
}
#[cfg(not(windows))]
fn force_udp(_sock: &std::net::UdpSocket, _index: u32) -> io::Result<()> {
    Ok(())
}

// ------------------------------------------------------------------ sockets bound to the modem card

// ------------------------------------------------------------------ per-destination host routes
//
// Some VPNs remove or hide the default route of the real network card. Then a socket that is
// locked to that card can still talk to the modem itself (on-link, so the modem DNS works) but
// every remote address fails with "network unreachable" (WSAENETUNREACH, 10051). In that case a
// /32 route "this address -> via the modem, on the real card" is added (needs Administrator).
// A /32 beats any VPN route by longest-prefix match, so only that one address is affected.
// Added routes are remembered in data/host_routes.txt and removed on exit / next start.

const MAX_HOST_ROUTES: usize = 1500;

fn routes() -> &'static Mutex<HashSet<Ipv4Addr>> {
    static R: OnceLock<Mutex<HashSet<Ipv4Addr>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashSet::new()))
}

fn route_lock() -> &'static tokio::sync::Mutex<()> {
    static L: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    L.get_or_init(|| tokio::sync::Mutex::new(()))
}

static ROUTE_LOG: OnceLock<PathBuf> = OnceLock::new();

pub fn init_route_log(path: PathBuf) {
    let _ = ROUTE_LOG.set(path);
}

fn already_routed(ip: Ipv4Addr) -> bool {
    routes().lock().unwrap_or_else(|e| e.into_inner()).contains(&ip)
}

/// WSAENETUNREACH / WSAEHOSTUNREACH
pub fn is_unreachable(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(10051) | Some(10065))
}

pub async fn ensure_host_route(nic: &NicInfo, ip: Ipv4Addr) -> Result<(), String> {
    let gw = nic.gateway.ok_or_else(|| "the modem address is unknown".to_string())?;
    let _guard = route_lock().lock().await;
    if already_routed(ip) {
        return Ok(());
    }
    let count = routes().lock().unwrap_or_else(|e| e.into_inner()).len();
    if count >= MAX_HOST_ROUTES {
        return Err(format!("{} host routes were already added; not adding more", MAX_HOST_ROUTES));
    }
    let (ip_s, gw_s, idx_s) = (ip.to_string(), gw.to_string(), nic.index.to_string());
    let out = tokio::task::spawn_blocking(move || {
        hidden_command("route")
            .args(["add", &ip_s, "mask", "255.255.255.255", &gw_s, "metric", "1", "if", &idx_s])
            .output()
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("cannot run 'route add': {}", e))?;
    if !out.status.success() {
        let text = format!("{} {}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        let text = text.trim().to_string();
        let hint = if text.to_ascii_lowercase().contains("elevation") {
            " (run the program as Administrator)"
        } else {
            ""
        };
        return Err(format!("'route add {}' failed: {}{}", ip, text, hint));
    }
    routes().lock().unwrap_or_else(|e| e.into_inner()).insert(ip);
    if let Some(p) = ROUTE_LOG.get() {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
            let _ = writeln!(f, "{}", ip);
        }
    }
    log_info!(
        "added a host route {} via the modem {} on {} (the VPN had hidden the default route of the modem card)",
        ip, gw, nic.name
    );
    Ok(())
}

fn delete_route(ip: Ipv4Addr) {
    let _ = hidden_command("route")
        .args(["delete", &ip.to_string(), "mask", "255.255.255.255"])
        .output();
}

/// Remove every host route this run added. Returns how many.
pub fn cleanup_host_routes() -> usize {
    let list: Vec<Ipv4Addr> = {
        let mut g = routes().lock().unwrap_or_else(|e| e.into_inner());
        g.drain().collect()
    };
    for ip in &list {
        delete_route(*ip);
    }
    if let Some(p) = ROUTE_LOG.get() {
        let _ = std::fs::remove_file(p);
    }
    list.len()
}

/// Remove routes a previous run (crash, closed window) left behind.
pub fn cleanup_stale_routes(path: &Path) -> usize {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return 0,
    };
    let mut n = 0;
    for line in text.lines() {
        if let Ok(ip) = line.trim().parse::<Ipv4Addr>() {
            delete_route(ip);
            n += 1;
        }
    }
    let _ = std::fs::remove_file(path);
    n
}

fn nic_ctx(nic: &NicInfo, e: io::Error) -> io::Error {
    let kind = e.kind();
    let msg = format!(
        "{} [through {} {} (interface {}), modem {}]",
        e,
        nic.name,
        nic.ip,
        nic.index,
        nic.gateway.map(|g| g.to_string()).unwrap_or_else(|| "unknown".to_string())
    );
    io::Error::new(kind, msg)
}

/// TCP connection through the real network card. If Windows says the network is unreachable
/// (the VPN hid the card's default route) a host route via the modem is added and it retries once.
async fn connect_once(nic: &NicInfo, ip: IpAddr, port: u16) -> io::Result<TcpStream> {
    match connect_once(nic, ip, port).await {
        Ok(s) => Ok(s),
        Err(e) if is_unreachable(&e) => {
            let v4 = match ip {
                IpAddr::V4(v) => v,
                IpAddr::V6(_) => return Err(nic_ctx(nic, e)),
            };
            if already_routed(v4) {
                return Err(nic_ctx(nic, e));
            }
            match ensure_host_route(nic, v4).await {
                Ok(()) => connect_once(nic, ip, port).await.map_err(|e2| nic_ctx(nic, e2)),
                Err(msg) => {
                    let kind = e.kind();
                    Err(io::Error::new(
                        kind,
                        format!("{} - and adding a route through the modem failed: {}", nic_ctx(nic, e), msg),
                    ))
                }
            }
        }
        Err(e) => Err(nic_ctx(nic, e)),
    }
}

/// TCP connection that leaves through the real network card (IP_UNICAST_IF + source bind),
/// so it reaches the modem directly even if a VPN adapter owns the default route.
pub async fn connect_tcp_on_nic(nic: &NicInfo, ip: IpAddr, port: u16) -> io::Result<TcpStream> {
    let v6 = ip.is_ipv6();
    let sock = if v6 { TcpSocket::new_v6()? } else { TcpSocket::new_v4()? };
    force_tcp(&sock, v6, nic.index)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot lock the socket to the modem card (index {}): {}", nic.index, e)))?;
    if !v6 {
        sock.bind(SocketAddr::new(IpAddr::V4(nic.ip), 0))?;
    }
    match tokio::time::timeout(Duration::from_secs(10), sock.connect(SocketAddr::new(ip, port))).await {
        Ok(r) => {
            let s = r?;
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, format!("connecting to {}:{} through the modem timed out", ip, port))),
    }
}

/// UDP socket that leaves through the real network card.
pub fn bind_udp_on_nic(nic: &NicInfo) -> io::Result<UdpSocket> {
    let std_sock = std::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(nic.ip), 0))?;
    force_udp(&std_sock, nic.index)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot lock the UDP socket to the modem card: {}", e)))?;
    std_sock.set_nonblocking(true)?;
    UdpSocket::from_std(std_sock)
}

// ------------------------------------------------------------------ NIC detection

#[cfg(windows)]
const PS_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$out = @()
foreach ($a in (Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' })) {
  $ip = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254*' } | Select-Object -First 1
  $gw = Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1
  if ($ip -and $gw -and $gw.NextHop -ne '0.0.0.0') {
    $out += [pscustomobject]@{ name = $a.Name; index = [int]$a.ifIndex; ip = $ip.IPAddress; gw = $gw.NextHop; metric = [int]$gw.RouteMetric }
  }
}
ConvertTo-Json -InputObject @($out) -Compress
"#;

fn run_route_print() -> Result<String, String> {
    let out = hidden_command("route")
        .args(["print", "-4"])
        .output()
        .map_err(|e| format!("cannot run 'route print': {}", e))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Find the physical network card (the one cabled/Wi-Fi'd to the modem), its index and the modem IP.
/// `manual_ip` / `manual_gw` ("auto" or an IPv4) override the detection.
pub async fn detect_nic(manual_ip: &str, manual_gw: &str) -> Result<NicInfo, String> {
    let mi = manual_ip.trim().to_string();
    let mg = manual_gw.trim().to_string();
    tokio::task::spawn_blocking(move || detect_nic_blocking(&mi, &mg))
        .await
        .map_err(|e| format!("NIC detection crashed: {}", e))?
}

fn is_auto(s: &str) -> bool {
    s.is_empty() || s.eq_ignore_ascii_case("auto")
}

#[cfg(windows)]
fn detect_nic_blocking(manual_ip: &str, manual_gw: &str) -> Result<NicInfo, String> {
    let gw_override: Option<Ipv4Addr> = if is_auto(manual_gw) {
        None
    } else {
        Some(manual_gw.parse().map_err(|_| format!("router_ip '{}' is not an IPv4 address", manual_gw))?)
    };

    if !is_auto(manual_ip) {
        let ip: Ipv4Addr = manual_ip.parse().map_err(|_| format!("nic_ip '{}' is not an IPv4 address", manual_ip))?;
        let index = ifindex_for_ip(ip).ok_or_else(|| format!("no adapter owns {} (check nic_ip)", ip))?;
        let gateway = gw_override.or_else(|| run_route_print().ok().and_then(|t| parse_route_print(&t, ip)));
        return Ok(NicInfo { name: "manual".into(), ip, index, gateway });
    }

    // 1) PowerShell: only physical adapters that are up and have a default route
    let ps = hidden_command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", PS_SCRIPT])
        .output();
    let mut ps_error = String::new();
    match ps {
        Ok(o) if o.status.success() => match parse_nic_json(&String::from_utf8_lossy(&o.stdout)) {
            Ok(list) => {
                if let Some((_, mut nic)) = list.into_iter().next() {
                    if let Some(g) = gw_override {
                        nic.gateway = Some(g);
                    }
                    return Ok(nic);
                }
                ps_error = "no physical adapter with a default route is up".into();
            }
            Err(e) => ps_error = e,
        },
        Ok(o) => ps_error = format!("powershell exited with {}", o.status),
        Err(e) => ps_error = format!("cannot run powershell: {}", e),
    }
    log_warn!("physical-adapter detection failed ({}); falling back to the routing table", ps_error);

    // 2) routing table only (cannot tell physical from virtual: set nic_ip if this picks wrong)
    let text = run_route_print()?;
    let (ip, gw) = parse_route_print_any(&text)
        .ok_or_else(|| "no default route found; connect to the modem or set nic_ip in Settings".to_string())?;
    let index = ifindex_for_ip(ip).ok_or_else(|| format!("no adapter owns {}", ip))?;
    log_warn!("using {} from the routing table; if a VPN adapter was picked, set nic_ip in Settings", ip);
    Ok(NicInfo { name: "from routing table".into(), ip, index, gateway: gw_override.or(Some(gw)) })
}

#[cfg(not(windows))]
fn detect_nic_blocking(manual_ip: &str, manual_gw: &str) -> Result<NicInfo, String> {
    if is_auto(manual_ip) {
        return Err("automatic network card detection only works on Windows; set nic_ip".into());
    }
    let ip: Ipv4Addr = manual_ip.parse().map_err(|_| format!("nic_ip '{}' is not an IPv4 address", manual_ip))?;
    let gateway = if is_auto(manual_gw) { None } else { manual_gw.parse().ok() };
    Ok(NicInfo { name: "manual".into(), ip, index: 1, gateway })
}

// ------------------------------------------------------------------ misc

/// Allow inbound TCP on the proxy port and inbound UDP for this program (needs Administrator).
pub fn add_firewall_rules(port: u16) -> bool {
    const RULE: &str = "VPN Share Proxy";
    let _ = hidden_command("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", RULE)])
        .output();
    let tcp = hidden_command("netsh")
        .args([
            "advfirewall", "firewall", "add", "rule", &format!("name={}", RULE), "dir=in", "action=allow",
            "protocol=TCP", &format!("localport={}", port),
        ])
        .output();
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
    let udp = hidden_command("netsh")
        .args([
            "advfirewall", "firewall", "add", "rule", &format!("name={}", RULE), "dir=in", "action=allow",
            "protocol=UDP", &format!("program={}", exe),
        ])
        .output();
    matches!((&tcp, &udp), (Ok(a), Ok(b)) if a.status.success() && b.status.success())
}

pub fn open_url(url: &str) {
    #[cfg(windows)]
    {
        if let Err(e) = hidden_command("cmd").args(["/C", "start", "", url]).spawn() {
            log_warn!("could not open the browser: {} (open {} yourself)", e, url);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = url;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: &str = "IPv4 Route Table\n===\nActive Routes:\nNetwork Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25\n          0.0.0.0        128.0.0.0         10.8.0.1       10.8.0.2      5\n          0.0.0.0          0.0.0.0         10.8.0.1       10.8.0.2      6\n          0.0.0.0          0.0.0.0         On-link      192.168.1.50   300\n";

    #[test]
    fn gateway_from_route_table() {
        assert_eq!(parse_route_print(ROUTE, "192.168.1.50".parse().unwrap()), Some("192.168.1.1".parse().unwrap()));
        assert_eq!(parse_route_print(ROUTE, "10.8.0.2".parse().unwrap()), Some("10.8.0.1".parse().unwrap()));
        assert_eq!(parse_route_print(ROUTE, "1.1.1.1".parse().unwrap()), None);
        // lowest metric overall is the VPN default route: documents why PowerShell detection comes first
        assert_eq!(parse_route_print_any(ROUTE).unwrap().0, "10.8.0.2".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn nic_json_object_and_array() {
        let one = r#"{"name":"Wi-Fi","index":12,"ip":"192.168.1.50","gw":"192.168.1.1","metric":25}"#;
        let l = parse_nic_json(one).unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].1.index, 12);
        let two = r#"[{"name":"A","index":3,"ip":"10.0.0.2","gw":"10.0.0.1","metric":50},{"name":"B","index":4,"ip":"192.168.1.50","gw":"192.168.1.1","metric":10}]"#;
        let l = parse_nic_json(two).unwrap();
        assert_eq!(l[0].1.name, "B");
        assert!(parse_nic_json("[]").unwrap().is_empty());
        assert!(parse_nic_json("garbage").is_err());
    }
}
