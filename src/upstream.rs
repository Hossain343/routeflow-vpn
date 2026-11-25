//! "ip net": the route Chrome uses (Windows system proxy / PAC / manual proxy / system-wide VPN).
//! Parsing, auto-detection, and the outbound SOCKS5 / HTTP-CONNECT clients (with authentication).
use crate::util::{fmt_host_port, invalid, parse_authority, pct_decode};
use base64::Engine;
use std::io;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpKind {
    Socks5,
    Http,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamSpec {
    pub kind: UpKind,
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
}

impl UpstreamSpec {
    pub fn describe(&self) -> String {
        let k = match self.kind {
            UpKind::Socks5 => "socks5",
            UpKind::Http => "http",
        };
        let a = if self.user.is_some() { " (with login)" } else { "" };
        format!("{} {}{}", k, fmt_host_port(&self.host, self.port), a)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamMode {
    Auto,
    Direct,
    Manual(UpstreamSpec),
}

/// `auto`, `direct`, `host:port` (HTTP, the Windows convention), `http://[user:pass@]host:port`,
/// `socks5://[user:pass@]host:port`. `def_user/def_pass` (Settings fields) override URL credentials.
pub fn parse_upstream_setting(s: &str, def_user: &str, def_pass: &str) -> Result<UpstreamMode, String> {
    let t = s.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("auto") {
        return Ok(UpstreamMode::Auto);
    }
    if t.eq_ignore_ascii_case("direct") {
        return Ok(UpstreamMode::Direct);
    }
    let mut spec = parse_proxy_url(t, UpKind::Http)?;
    if !def_user.is_empty() {
        spec.user = Some(def_user.to_string());
        spec.pass = Some(def_pass.to_string());
    }
    Ok(UpstreamMode::Manual(spec))
}

pub fn parse_proxy_url(text: &str, default_kind: UpKind) -> Result<UpstreamSpec, String> {
    let mut t = text.trim();
    let mut kind = default_kind;
    if let Some((scheme, rest)) = t.split_once("://") {
        match scheme.to_ascii_lowercase().as_str() {
            "socks5" | "socks5h" | "socks" => kind = UpKind::Socks5,
            "http" | "proxy" => kind = UpKind::Http,
            "https" => return Err("https:// proxies are not supported (use http:// or socks5://)".into()),
            "socks4" | "socks4a" => return Err("SOCKS4 is not supported (use socks5://)".into()),
            other => return Err(format!("unsupported proxy scheme '{}'", other)),
        }
        t = rest;
    }
    let t = t.split('/').next().unwrap_or("");
    let (userinfo, hostport) = match t.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, t),
    };
    let (host, port) = parse_authority(hostport, None)?;
    let (user, pass) = match userinfo {
        Some(u) => {
            let (a, b) = u.split_once(':').unwrap_or((u, ""));
            (Some(pct_decode(a)), Some(pct_decode(b)))
        }
        None => (None, None),
    };
    Ok(UpstreamSpec { kind, host, port, user, pass })
}

/// Windows `ProxyServer` value: `host:port` or `http=h:p;https=h:p;socks=h:p` (socks preferred).
pub fn parse_proxy_server(server: &str) -> Option<UpstreamSpec> {
    let server = server.trim();
    if server.is_empty() {
        return None;
    }
    if server.contains('=') {
        let mut socks: Option<UpstreamSpec> = None;
        let mut https: Option<UpstreamSpec> = None;
        let mut http: Option<UpstreamSpec> = None;
        for part in server.split(';') {
            if let Some((scheme, addr)) = part.split_once('=') {
                let addr = addr.trim();
                match scheme.trim().to_ascii_lowercase().as_str() {
                    "socks" | "socks5" => socks = parse_proxy_url(addr, UpKind::Socks5).ok(),
                    "https" => https = parse_proxy_url(addr, UpKind::Http).ok(),
                    "http" => http = parse_proxy_url(addr, UpKind::Http).ok(),
                    _ => {}
                }
            }
        }
        return socks.or(https).or(http);
    }
    parse_proxy_url(server.split(';').next().unwrap_or(""), UpKind::Http).ok()
}

// ------------------------------------------------------------------ PAC scripts

/// Remove `// ...` and `/* ... */` comments (outside string literals) so commented-out
/// `PROXY x:y` rules are never picked up.
pub fn strip_js_comments(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut quote: Option<char> = None;
    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = quote {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            quote = Some(c);
            out.push(c);
            i += 1;
            continue;
        }
        if c == '/' && i + 1 < chars.len() {
            if chars[i + 1] == '/' {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            if chars[i + 1] == '*' {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
                out.push(' ');
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

fn string_literals(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut esc = false;
    for c in src.chars() {
        match quote {
            Some(q) => {
                if esc {
                    cur.push(c);
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == q {
                    out.push(std::mem::take(&mut cur));
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                }
            }
        }
    }
    out
}

/// First usable `SOCKS5/SOCKS x:y` (preferred) or `PROXY x:y` found in a PAC script's string
/// literals. We do not execute the JavaScript, so per-URL rules are not evaluated.
pub fn extract_pac_proxy(src: &str) -> Option<UpstreamSpec> {
    let clean = strip_js_comments(src);
    let mut socks: Option<UpstreamSpec> = None;
    let mut http: Option<UpstreamSpec> = None;
    for lit in string_literals(&clean) {
        for part in lit.split(';') {
            let part = part.trim();
            let (word, rest) = match part.split_once(char::is_whitespace) {
                Some(x) => x,
                None => continue,
            };
            let rest = rest.trim();
            match word.to_ascii_uppercase().as_str() {
                "SOCKS" | "SOCKS5" => {
                    if socks.is_none() {
                        socks = parse_proxy_url(rest, UpKind::Socks5).ok();
                    }
                }
                "PROXY" | "HTTP" => {
                    if http.is_none() {
                        http = parse_proxy_url(rest, UpKind::Http).ok();
                    }
                }
                _ => {}
            }
        }
    }
    socks.or(http)
}

// ------------------------------------------------------------------ Windows system proxy

#[derive(Default, Debug)]
pub struct SystemProxyInfo {
    pub spec: Option<UpstreamSpec>,
    pub pac_url: Option<String>,
    pub auto_detect: bool,
    pub error: Option<String>,
}

#[cfg(windows)]
pub fn read_system_proxy() -> SystemProxyInfo {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let key = match RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
    {
        Ok(k) => k,
        Err(e) => {
            return SystemProxyInfo { error: Some(format!("cannot open Internet Settings: {}", e)), ..Default::default() }
        }
    };
    let enable: u32 = key.get_value("ProxyEnable").unwrap_or(0);
    let server: String = key.get_value("ProxyServer").unwrap_or_default();
    let pac: String = key.get_value("AutoConfigURL").unwrap_or_default();
    // flags byte of DefaultConnectionSettings: 0x02 proxy, 0x04 PAC url, 0x08 auto-detect (WPAD)
    let auto_detect = key
        .open_subkey("Connections")
        .ok()
        .and_then(|c| c.get_raw_value("DefaultConnectionSettings").ok())
        .map(|v| v.bytes.len() > 8 && (v.bytes[8] & 0x08) != 0)
        .unwrap_or(false);
    let spec = if enable != 0 { parse_proxy_server(&server) } else { None };
    let pac_url = if pac.trim().is_empty() { None } else { Some(pac.trim().to_string()) };
    SystemProxyInfo { spec, pac_url, auto_detect, error: None }
}

#[cfg(not(windows))]
pub fn read_system_proxy() -> SystemProxyInfo {
    SystemProxyInfo::default()
}

/// Decides where the VPN route goes right now. Cheap to clone-by-rebuild; one per settings snapshot.
pub struct UpstreamResolver {
    mode: UpstreamMode,
    own_port: u16,
    own_hosts: Vec<String>,
    cache: Mutex<Option<(Instant, Option<UpstreamSpec>)>>,
    warned: Mutex<Vec<String>>,
}

impl UpstreamResolver {
    pub fn new(mode: UpstreamMode, own_port: u16, own_hosts: Vec<String>) -> Self {
        let mut hosts = vec!["127.0.0.1".to_string(), "localhost".into(), "0.0.0.0".into(), "::1".into()];
        hosts.extend(own_hosts);
        UpstreamResolver { mode, own_port, own_hosts: hosts, cache: Mutex::new(None), warned: Mutex::new(Vec::new()) }
    }

    fn warn_once(&self, key: &str, msg: String) {
        let mut w = self.warned.lock().unwrap_or_else(|e| e.into_inner());
        if !w.iter().any(|k| k == key) {
            w.push(key.to_string());
            log_warn!("{}", msg);
        }
    }

    /// Never forward into ourselves (a proxy that points at our own listening port would loop).
    fn is_self(&self, s: &UpstreamSpec) -> bool {
        s.port == self.own_port && self.own_hosts.iter().any(|h| h.eq_ignore_ascii_case(&s.host))
    }

    pub async fn current(&self) -> Option<UpstreamSpec> {
        match &self.mode {
            UpstreamMode::Direct => None,
            UpstreamMode::Manual(spec) => {
                if self.is_self(spec) {
                    self.warn_once("self-manual", format!("upstream {} points at this proxy itself; ignoring it", spec.describe()));
                    None
                } else {
                    Some(spec.clone())
                }
            }
            UpstreamMode::Auto => {
                {
                    let c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some((t, v)) = c.as_ref() {
                        if t.elapsed() < Duration::from_secs(3) {
                            return v.clone();
                        }
                    }
                }
                let v = self.detect_auto().await;
                *self.cache.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), v.clone()));
                v
            }
        }
    }

    pub async fn describe(&self) -> String {
        match &self.mode {
            UpstreamMode::Direct => "direct (system-wide VPN, no proxy)".to_string(),
            UpstreamMode::Manual(s) => format!("manual: {}", s.describe()),
            UpstreamMode::Auto => match self.current().await {
                Some(s) => format!("auto (Windows system proxy): {}", s.describe()),
                None => "auto: no system proxy found -> normal route (system-wide VPN)".to_string(),
            },
        }
    }

    async fn detect_auto(&self) -> Option<UpstreamSpec> {
        let info = tokio::task::spawn_blocking(read_system_proxy).await.unwrap_or_else(|e| SystemProxyInfo {
            error: Some(format!("registry reader crashed: {}", e)),
            ..Default::default()
        });
        if let Some(err) = &info.error {
            self.warn_once("regerr", format!("Windows proxy settings unreadable: {}", err));
        }
        let mut found = info.spec.clone();
        if found.is_none() {
            if let Some(url) = &info.pac_url {
                found = self.pac_spec(url).await;
            } else if info.auto_detect {
                self.warn_once(
                    "wpad",
                    "Windows 'Automatically detect settings' (WPAD) is on but no proxy/PAC is configured; \
                     cannot evaluate WPAD, using the normal route. Set 'upstream' in Settings if your VPN needs a proxy."
                        .to_string(),
                );
            }
        }
        if let Some(s) = &found {
            if self.is_self(s) {
                self.warn_once("self-auto", format!("the Windows system proxy {} is this proxy itself; ignoring it", s.describe()));
                return None;
            }
        }
        found
    }

    async fn pac_spec(&self, url: &str) -> Option<UpstreamSpec> {
        let text = match load_pac(url).await {
            Ok(t) => t,
            Err(e) => {
                self.warn_once(&format!("pac:{}", url), format!("cannot read the PAC script {}: {}", url, e));
                return None;
            }
        };
        let spec = extract_pac_proxy(&text);
        if spec.is_none() {
            self.warn_once(&format!("pacnone:{}", url), format!("the PAC script {} has no PROXY/SOCKS rule we can use", url));
        }
        spec
    }
}

async fn load_pac(url: &str) -> Result<String, String> {
    if let Some(rest) = url.strip_prefix("file:") {
        let p = rest.trim_start_matches('/');
        let p = p.strip_prefix("localhost/").unwrap_or(p);
        let path = crate::util::pct_decode(p);
        return tokio::fs::read_to_string(&path).await.map_err(|e| format!("{}: {}", path, e));
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(4))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    resp.text().await.map_err(|e| e.to_string())
}

// ------------------------------------------------------------------ outbound connections

/// Open a TCP connection to `host:port` the way the VPN route does it:
/// `None` = the normal Windows route (a system-wide VPN owns it), `Some` = through that proxy.
pub async fn connect_vpn(up: Option<&UpstreamSpec>, host: &str, port: u16) -> io::Result<TcpStream> {
    match up {
        None => {
            match tokio::time::timeout(Duration::from_secs(15), TcpStream::connect((host, port))).await {
                Ok(r) => {
                    let s = r?;
                    let _ = s.set_nodelay(true);
                    Ok(s)
                }
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, format!("connecting to {} timed out", fmt_host_port(host, port)))),
            }
        }
        Some(spec) => connect_via(spec, host, port).await,
    }
}

async fn connect_via(spec: &UpstreamSpec, host: &str, port: u16) -> io::Result<TcpStream> {
    let mut s = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((spec.host.as_str(), spec.port)))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("upstream proxy {} did not answer", fmt_host_port(&spec.host, spec.port)),
            )
        })??;
    let _ = s.set_nodelay(true);
    let step = tokio::time::timeout(Duration::from_secs(15), async {
        match spec.kind {
            UpKind::Socks5 => socks5_connect(&mut s, spec, host, port).await,
            UpKind::Http => http_connect(&mut s, spec, host, port).await,
        }
    })
    .await;
    match step {
        Ok(Ok(())) => Ok(s),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "upstream proxy handshake timed out")),
    }
}

/// SOCKS5 greeting + optional username/password sub-negotiation (RFC 1929).
pub async fn socks5_handshake(s: &mut TcpStream, spec: &UpstreamSpec) -> io::Result<()> {
    let creds: Option<(&str, &str)> = match (&spec.user, &spec.pass) {
        (Some(u), p) => Some((u.as_str(), p.as_deref().unwrap_or(""))),
        _ => None,
    };
    if creds.is_some() {
        s.write_all(&[5, 2, 0, 2]).await?;
    } else {
        s.write_all(&[5, 1, 0]).await?;
    }
    let mut rep = [0u8; 2];
    s.read_exact(&mut rep).await?;
    if rep[0] != 5 {
        return Err(invalid("the upstream is not a SOCKS5 proxy"));
    }
    match rep[1] {
        0 => {}
        2 => {
            let (u, p) = creds.ok_or_else(|| invalid("the upstream SOCKS5 proxy wants a username/password (set it in Settings)"))?;
            if u.len() > 255 || p.len() > 255 {
                return Err(invalid("upstream username/password longer than 255 bytes"));
            }
            let mut msg = vec![1u8, u.len() as u8];
            msg.extend_from_slice(u.as_bytes());
            msg.push(p.len() as u8);
            msg.extend_from_slice(p.as_bytes());
            s.write_all(&msg).await?;
            let mut r2 = [0u8; 2];
            s.read_exact(&mut r2).await?;
            if r2[1] != 0 {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the upstream SOCKS5 proxy rejected our username/password"));
            }
        }
        0xFF => return Err(invalid("the upstream SOCKS5 proxy accepts none of our login methods")),
        m => return Err(invalid(format!("the upstream SOCKS5 proxy chose an unsupported method ({})", m))),
    }
    Ok(())
}

pub async fn skip_socks_bound_addr(s: &mut TcpStream, atyp: u8) -> io::Result<()> {
    let n = match atyp {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        other => return Err(invalid(format!("bad address type {} in the upstream reply", other))),
    };
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await?;
    Ok(())
}

async fn socks5_connect(s: &mut TcpStream, spec: &UpstreamSpec, host: &str, port: u16) -> io::Result<()> {
    socks5_handshake(s, spec).await?;
    let mut req = vec![5u8, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            req.push(1);
            req.extend_from_slice(&a.octets());
        }
        Ok(IpAddr::V6(a)) => {
            req.push(4);
            req.extend_from_slice(&a.octets());
        }
        Err(_) => {
            let hb = host.as_bytes();
            if hb.len() > 255 {
                return Err(invalid("host name longer than 255 bytes"));
            }
            req.push(3);
            req.push(hb.len() as u8);
            req.extend_from_slice(hb);
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(invalid("bad SOCKS5 reply from the upstream"));
    }
    if head[1] != 0 {
        let (kind, why) = match head[1] {
            2 => (io::ErrorKind::PermissionDenied, "connection not allowed by the upstream ruleset"),
            3 => (io::ErrorKind::Other, "network unreachable"),
            4 => (io::ErrorKind::Other, "host unreachable"),
            5 => (io::ErrorKind::ConnectionRefused, "connection refused"),
            6 => (io::ErrorKind::TimedOut, "TTL expired"),
            7 => (io::ErrorKind::Other, "command not supported"),
            8 => (io::ErrorKind::Other, "address type not supported"),
            _ => (io::ErrorKind::Other, "general failure"),
        };
        return Err(io::Error::new(kind, format!("upstream SOCKS5 refused {}: {}", fmt_host_port(host, port), why)));
    }
    skip_socks_bound_addr(s, head[3]).await
}

async fn http_connect(s: &mut TcpStream, spec: &UpstreamSpec, host: &str, port: u16) -> io::Result<()> {
    let hp = fmt_host_port(host, port);
    let mut req = format!("CONNECT {hp} HTTP/1.1\r\nHost: {hp}\r\nProxy-Connection: keep-alive\r\n");
    if let Some(u) = &spec.user {
        let cred = format!("{}:{}", u, spec.pass.as_deref().unwrap_or(""));
        let b64 = base64::engine::general_purpose::STANDARD.encode(cred);
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", b64));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    // read byte by byte so nothing after the header is consumed
    let mut head: Vec<u8> = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    loop {
        s.read_exact(&mut b).await?;
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 16 * 1024 {
            return Err(invalid("the upstream HTTP proxy sent a header that is too large"));
        }
    }
    let first_line = String::from_utf8_lossy(head.split(|&c| c == b'\n').next().unwrap_or(&[])).trim().to_string();
    let code: u16 = first_line.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    match code {
        200..=299 => Ok(()),
        407 => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the upstream HTTP proxy wants a login (407); set the upstream username/password",
        )),
        _ => Err(io::Error::new(io::ErrorKind::Other, format!("the upstream HTTP proxy answered '{}'", first_line))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setting_variants() {
        assert_eq!(parse_upstream_setting("auto", "", "").unwrap(), UpstreamMode::Auto);
        assert_eq!(parse_upstream_setting("DIRECT", "", "").unwrap(), UpstreamMode::Direct);
        match parse_upstream_setting("127.0.0.1:10809", "", "").unwrap() {
            UpstreamMode::Manual(s) => assert_eq!((s.kind, s.port), (UpKind::Http, 10809)),
            _ => panic!(),
        }
        match parse_upstream_setting("socks5://u%40x:p%3Aw@[::1]:1080", "", "").unwrap() {
            UpstreamMode::Manual(s) => {
                assert_eq!(s.kind, UpKind::Socks5);
                assert_eq!(s.host, "::1");
                assert_eq!(s.user.as_deref(), Some("u@x"));
                assert_eq!(s.pass.as_deref(), Some("p:w"));
            }
            _ => panic!(),
        }
        match parse_upstream_setting("socks5://h:1", "bob", "pw").unwrap() {
            UpstreamMode::Manual(s) => assert_eq!(s.user.as_deref(), Some("bob")),
            _ => panic!(),
        }
        assert!(parse_upstream_setting("https://h:1", "", "").is_err());
        assert!(parse_upstream_setting("socks4://h:1", "", "").is_err());
        assert!(parse_upstream_setting("h", "", "").is_err());
    }

    #[test]
    fn windows_proxy_server_strings() {
        let s = parse_proxy_server("127.0.0.1:10809").unwrap();
        assert_eq!((s.kind, s.port), (UpKind::Http, 10809));
        let s = parse_proxy_server("http=127.0.0.1:1;https=127.0.0.1:2;socks=127.0.0.1:3").unwrap();
        assert_eq!((s.kind, s.port), (UpKind::Socks5, 3));
        let s = parse_proxy_server("http=127.0.0.1:1;https=127.0.0.1:2").unwrap();
        assert_eq!(s.port, 2);
        assert!(parse_proxy_server("").is_none());
    }

    #[test]
    fn pac_comments_are_ignored() {
        let pac = r#"
            function FindProxyForURL(url, host) {
                // return "PROXY 9.9.9.9:9999";
                /* return "SOCKS 8.8.8.8:8888"; */
                var u = "http://example.com//x"; // trailing
                return "PROXY 127.0.0.1:10809; DIRECT";
            }"#;
        let s = extract_pac_proxy(pac).unwrap();
        assert_eq!((s.host.as_str(), s.port), ("127.0.0.1", 10809));
        let pac2 = r#"function f(u,h){ return "SOCKS5 127.0.0.1:1080; PROXY 127.0.0.1:1081"; }"#;
        assert_eq!(extract_pac_proxy(pac2).unwrap().kind, UpKind::Socks5);
        assert!(extract_pac_proxy("// return \"PROXY 1.1.1.1:1\";").is_none());
    }
}
