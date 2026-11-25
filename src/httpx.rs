//! Inbound HTTP proxy: HTTPS via CONNECT (tunnel) and plain `http://` requests with real
//! keep-alive (request/response framing is parsed, so connections are reused and no
//! `Connection: close` is forced). Also holds the small buffered reader the UI server reuses.
use crate::proxy::{self, ConnectError, Flow, Target};
use crate::rules::Route;
use crate::state::Shared;
use crate::util::{ct_eq, find_subslice, invalid, is_benign, parse_authority};
use base64::Engine;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub const MAX_HEAD: usize = 64 * 1024;
const MAX_LINE: usize = 8 * 1024;

// ------------------------------------------------------------------ buffered reader

/// A stream with a read-ahead buffer, so bytes read past a header are never lost.
pub struct Buffered<S> {
    pub inner: S,
    buf: Vec<u8>,
    start: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Buffered<S> {
    pub fn new(inner: S) -> Self {
        Buffered { inner, buf: Vec::with_capacity(8192), start: 0 }
    }

    fn unread(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    async fn fill(&mut self) -> io::Result<usize> {
        if self.start > 0 && self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
        let mut tmp = [0u8; 8192];
        let n = self.inner.read(&mut tmp).await?;
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }

    /// Everything up to and including the blank line. `None` = clean EOF before any byte.
    pub async fn read_head(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(pos) = find_subslice(self.unread(), b"\r\n\r\n") {
                let end = self.start + pos + 4;
                let head = self.buf[self.start..end].to_vec();
                self.start = end;
                return Ok(Some(head));
            }
            if self.unread().len() > MAX_HEAD {
                return Err(invalid("header block too large"));
            }
            if self.fill().await? == 0 {
                return if self.unread().is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed inside a header block"))
                };
            }
        }
    }

    /// One line including its `\n`.
    pub async fn read_line(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(pos) = self.unread().iter().position(|&b| b == b'\n') {
                let end = self.start + pos + 1;
                let line = self.buf[self.start..end].to_vec();
                self.start = end;
                return Ok(line);
            }
            if self.unread().len() > MAX_LINE {
                return Err(invalid("line too long"));
            }
            if self.fill().await? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed inside a message body"));
            }
        }
    }

    pub async fn read_exact_vec(&mut self, n: usize) -> io::Result<Vec<u8>> {
        while self.unread().len() < n {
            if self.fill().await? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed inside a message body"));
            }
        }
        let out = self.buf[self.start..self.start + n].to_vec();
        self.start += n;
        Ok(out)
    }

    /// Forward exactly `n` body bytes to `w`.
    pub async fn copy_exact_to<W: AsyncWrite + Unpin>(&mut self, w: &mut W, mut n: u64) -> io::Result<()> {
        while n > 0 {
            if self.unread().is_empty() && self.fill().await? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed inside a message body"));
            }
            let take = std::cmp::min(n, self.unread().len() as u64) as usize;
            w.write_all(&self.buf[self.start..self.start + take]).await?;
            self.start += take;
            n -= take as u64;
        }
        Ok(())
    }

    /// Forward everything until EOF (response bodies without a length).
    pub async fn copy_to_end<W: AsyncWrite + Unpin>(&mut self, w: &mut W) -> io::Result<u64> {
        let mut total = 0u64;
        loop {
            if !self.unread().is_empty() {
                w.write_all(&self.buf[self.start..]).await?;
                total += self.unread().len() as u64;
                self.start = self.buf.len();
            }
            if self.fill().await? == 0 {
                return Ok(total);
            }
        }
    }

    pub fn into_parts(self) -> (S, Vec<u8>) {
        let rest = self.buf[self.start..].to_vec();
        (self.inner, rest)
    }
}

// ------------------------------------------------------------------ message parsing

pub struct Head {
    pub first: String,
    pub headers: Vec<(String, String)>,
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

fn to_latin1(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u32 as u8).collect()
}

pub fn parse_head(raw: &[u8]) -> Result<Head, String> {
    let text = latin1(raw);
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or("").to_string();
    if first.is_empty() {
        return Err("empty start line".into());
    }
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        match l.split_once(':') {
            Some((k, v)) => headers.push((k.trim().to_string(), v.trim().to_string())),
            None => return Err(format!("malformed header line '{}'", l)),
        }
    }
    Ok(Head { first, headers })
}

pub fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn wants_keepalive(version: &str, headers: &[(String, String)]) -> bool {
    let conn = header(headers, "connection").map(|v| v.to_ascii_lowercase()).unwrap_or_default();
    let has = |t: &str| conn.split(',').any(|x| x.trim() == t);
    if version.eq_ignore_ascii_case("HTTP/1.0") {
        has("keep-alive")
    } else {
        !has("close")
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Body {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

fn request_body(headers: &[(String, String)]) -> Result<Body, String> {
    if let Some(te) = header(headers, "transfer-encoding") {
        if te.to_ascii_lowercase().contains("chunked") {
            return Ok(Body::Chunked);
        }
        return Err(format!("unsupported Transfer-Encoding '{}'", te));
    }
    match header(headers, "content-length") {
        Some(v) => match v.trim().parse::<u64>() {
            Ok(0) => Ok(Body::None),
            Ok(n) => Ok(Body::Length(n)),
            Err(_) => Err(format!("invalid Content-Length '{}'", v)),
        },
        None => Ok(Body::None),
    }
}

fn response_body(method: &str, status: u16, headers: &[(String, String)]) -> Result<Body, String> {
    if method.eq_ignore_ascii_case("HEAD") || (100..200).contains(&status) || status == 204 || status == 304 {
        return Ok(Body::None);
    }
    if let Some(te) = header(headers, "transfer-encoding") {
        if te.to_ascii_lowercase().contains("chunked") {
            return Ok(Body::Chunked);
        }
    }
    match header(headers, "content-length") {
        Some(v) => match v.trim().parse::<u64>() {
            Ok(0) => Ok(Body::None),
            Ok(n) => Ok(Body::Length(n)),
            Err(_) => Err(format!("invalid Content-Length '{}' from the server", v)),
        },
        None => Ok(Body::UntilClose),
    }
}

fn parse_status(first: &str) -> u16 {
    first.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
}

/// `http://[user@]host[:port]/path?query` -> (host, port, path+query). Port defaults to 80.
pub fn parse_absolute_http(target: &str) -> Result<(String, u16, String), String> {
    let lower = target.to_ascii_lowercase();
    let rest: &str = if lower.starts_with("http://") {
        &target[7..]
    } else if lower.starts_with("https://") {
        return Err("https:// targets must use CONNECT through a proxy".into());
    } else if target.starts_with('/') {
        return Err("this port is a proxy: set it as the proxy in your client instead of opening it like a web site".into());
    } else {
        return Err(format!("unsupported request target '{}'", target.chars().take(80).collect::<String>()));
    };
    let end = rest.find(|c: char| c == '/' || c == '?' || c == '#').unwrap_or(rest.len());
    let authority = &rest[..end];
    let mut path = rest[end..].to_string();
    if let Some(h) = path.find('#') {
        path.truncate(h);
    }
    if path.is_empty() || path.starts_with('?') {
        path.insert(0, '/');
    }
    let authority = authority.rsplit_once('@').map(|x| x.1).unwrap_or(authority);
    let (host, port) = parse_authority(authority, Some(80))?;
    Ok((host, port, path))
}

fn authorized(headers: &[(String, String)], user: &str, pass: &str) -> bool {
    let v = match header(headers, "proxy-authorization") {
        Some(v) => v,
        None => return false,
    };
    let mut it = v.split_whitespace();
    if !it.next().map(|s| s.eq_ignore_ascii_case("basic")).unwrap_or(false) {
        return false;
    }
    let b64 = match it.next() {
        Some(b) => b,
        None => return false,
    };
    match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(raw) => ct_eq(&raw, format!("{}:{}", user, pass).as_bytes()),
        Err(_) => false,
    }
}

fn build_forward_head(method: &str, path: &str, version: &str, headers: &[(String, String)], host: &str, port: u16) -> Vec<u8> {
    let mut s = String::with_capacity(512);
    s.push_str(&format!("{} {} {}\r\n", method, path, version));
    let mut has_host = false;
    for (k, v) in headers {
        let kl = k.to_ascii_lowercase();
        if kl == "proxy-authorization" || kl == "proxy-connection" || kl == "expect" {
            continue;
        }
        if kl == "host" {
            has_host = true;
        }
        s.push_str(&format!("{}: {}\r\n", k, v));
    }
    if !has_host {
        let hp = if port == 80 { host.to_string() } else { crate::util::fmt_host_port(host, port) };
        s.push_str(&format!("Host: {}\r\n", hp));
    }
    s.push_str("\r\n");
    to_latin1(&s)
}

async fn relay_chunked<R, W>(src: &mut Buffered<R>, dst: &mut W) -> io::Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let line = src.read_line().await?;
        dst.write_all(&line).await?;
        let text = String::from_utf8_lossy(&line).into_owned();
        let size_str = text.trim().split(';').next().unwrap_or("").trim().to_string();
        let size = u64::from_str_radix(&size_str, 16).map_err(|_| invalid(format!("bad chunk size '{}'", size_str)))?;
        if size == 0 {
            loop {
                let l = src.read_line().await?;
                dst.write_all(&l).await?;
                if l.as_slice() == b"\r\n" || l.as_slice() == b"\n" {
                    return Ok(());
                }
            }
        }
        src.copy_exact_to(dst, size).await?;
        let crlf = src.read_line().await?;
        dst.write_all(&crlf).await?;
    }
}

/// A complete small response, flushed and closed gracefully (so the client really receives it).
pub async fn send_simple(client: &mut TcpStream, code: u16, reason: &str, body: &str, extra: &[(&str, &str)]) -> io::Result<()> {
    let mut s = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n",
        code,
        reason,
        body.len()
    );
    for (k, v) in extra {
        s.push_str(&format!("{}: {}\r\n", k, v));
    }
    s.push_str("\r\n");
    s.push_str(body);
    client.write_all(s.as_bytes()).await?;
    client.flush().await?;
    let _ = client.shutdown().await;
    Ok(())
}

fn status_for(e: &ConnectError) -> (u16, &'static str) {
    match e {
        ConnectError::Blocked(_) => (403, "Forbidden"),
        ConnectError::Timeout(_) => (504, "Gateway Timeout"),
        _ => (502, "Bad Gateway"),
    }
}

fn short(s: &str) -> String {
    s.chars().take(100).collect()
}

// ------------------------------------------------------------------ the proxy

struct Upstream {
    key: String,
    conn: Buffered<TcpStream>,
    route: Route,
}

pub async fn handle(st: &Arc<Shared>, client: TcpStream, peer: SocketAddr) {
    if let Err(e) = serve(st, client, peer).await {
        if !is_benign(&e) {
            log_warn!("[{}] HTTP: {}", peer, e);
        }
    }
}

async fn open_upstream(st: &Arc<Shared>, peer: SocketAddr, kind: &str, t: &Target) -> Result<Upstream, ConnectError> {
    let o = proxy::open_outbound(st, peer, kind, t).await?;
    Ok(Upstream { key: t.display(), conn: Buffered::new(o.stream), route: o.route })
}

async fn serve(st: &Arc<Shared>, client: TcpStream, peer: SocketAddr) -> io::Result<()> {
    let mut c = Buffered::new(client);
    let mut up: Option<Upstream> = None;
    loop {
        let raw = match tokio::time::timeout(Duration::from_secs(120), c.read_head()).await {
            Err(_) => return Ok(()), // idle keep-alive connection: close quietly
            Ok(Ok(Some(h))) => h,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(e)) => {
                if e.kind() == io::ErrorKind::InvalidData {
                    let _ = send_simple(&mut c.inner, 431, "Request Header Fields Too Large", "request header too large\n", &[]).await;
                }
                return Err(e);
            }
        };
        let head = match parse_head(&raw) {
            Ok(h) => h,
            Err(m) => {
                let _ = send_simple(&mut c.inner, 400, "Bad Request", &format!("{}\n", m), &[]).await;
                return Err(invalid(m));
            }
        };
        let mut parts = head.first.splitn(3, ' ');
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();
        let version = parts.next().unwrap_or("").trim().to_string();
        if method.is_empty() || target.is_empty() || !version.to_ascii_uppercase().starts_with("HTTP/") {
            let _ = send_simple(&mut c.inner, 400, "Bad Request", "malformed request line\n", &[]).await;
            return Err(invalid(format!("malformed request line '{}'", short(&head.first))));
        }

        let settings = st.settings.load_full();
        if !settings.username.is_empty() && !authorized(&head.headers, &settings.username, &settings.password) {
            log_warn!("[{}] HTTP proxy login missing or wrong", peer);
            send_simple(
                &mut c.inner,
                407,
                "Proxy Authentication Required",
                "proxy login required\n",
                &[("Proxy-Authenticate", "Basic realm=\"VPN Share Proxy\"")],
            )
            .await?;
            return Ok(());
        }

        if method.eq_ignore_ascii_case("CONNECT") {
            return connect_tunnel(st, c, peer, &target).await;
        }

        // ---- plain http:// request
        let (host, port, path) = match parse_absolute_http(&target) {
            Ok(x) => x,
            Err(m) => {
                log_warn!("[{}] HTTP: {} (request: {} {})", peer, m, method, short(&target));
                send_simple(&mut c.inner, 400, "Bad Request", &format!("{}\n", m), &[]).await?;
                return Ok(());
            }
        };
        let req_body = match request_body(&head.headers) {
            Ok(b) => b,
            Err(m) => {
                log_warn!("[{}] HTTP: {} (request: {} {})", peer, m, method, short(&target));
                send_simple(&mut c.inner, 400, "Bad Request", &format!("{}\n", m), &[]).await?;
                return Ok(());
            }
        };
        let has_body = req_body != Body::None;
        let t = Target::new(&host, port);
        let key = t.display();
        let fwd_head = build_forward_head(&method, &path, &version, &head.headers, &host, port);
        let expect_continue = header(&head.headers, "expect")
            .map(|v| v.to_ascii_lowercase().contains("100-continue"))
            .unwrap_or(false);

        // reuse the previous origin connection only for body-less requests to the same host
        let mut cur: Option<Upstream> = None;
        if !has_body {
            if let Some(u) = up.take() {
                if u.key == key {
                    cur = Some(u);
                }
            }
        }
        up = None;
        let mut tries_left = if cur.is_some() { 2 } else { 1 };

        let (mut u, resp_raw): (Upstream, Vec<u8>) = loop {
            let mut u = match cur.take() {
                Some(u) => u,
                None => match open_upstream(st, peer, &method, &t).await {
                    Ok(u) => u,
                    Err(e) => {
                        let (code, reason) = status_for(&e);
                        send_simple(&mut c.inner, code, reason, &format!("{}\n", e), &[]).await?;
                        return Ok(());
                    }
                },
            };
            if let Err(e) = u.conn.inner.write_all(&fwd_head).await {
                if tries_left > 1 {
                    tries_left -= 1; // stale kept-alive connection: open a fresh one
                    continue;
                }
                log_warn!("[{}] {} {} => {}: sending the request failed: {}", peer, method, key, u.route.as_str(), e);
                send_simple(&mut c.inner, 502, "Bad Gateway", &format!("sending the request failed: {}\n", e), &[]).await?;
                return Ok(());
            }
            if has_body {
                if expect_continue {
                    c.inner.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
                    c.inner.flush().await?;
                }
                match &req_body {
                    Body::Length(n) => c.copy_exact_to(&mut u.conn.inner, *n).await?,
                    Body::Chunked => relay_chunked(&mut c, &mut u.conn.inner).await?,
                    _ => {}
                }
            }
            match u.conn.read_head().await {
                Ok(Some(h)) => break (u, h),
                other => {
                    if !has_body && tries_left > 1 {
                        tries_left -= 1;
                        continue;
                    }
                    let why = match other {
                        Err(e) => e.to_string(),
                        _ => "the server closed the connection without answering".to_string(),
                    };
                    log_warn!("[{}] {} {} => {}: no response: {}", peer, method, key, u.route.as_str(), why);
                    send_simple(&mut c.inner, 502, "Bad Gateway", &format!("no response from the server: {}\n", why), &[]).await?;
                    return Ok(());
                }
            }
        };

        // ---- response (skip interim 1xx answers, forwarding them)
        let mut raw_resp = resp_raw;
        let (rh, status) = loop {
            let rh = match parse_head(&raw_resp) {
                Ok(h) => h,
                Err(m) => {
                    log_warn!("[{}] {} {} => {}: bad response: {}", peer, method, key, u.route.as_str(), m);
                    send_simple(&mut c.inner, 502, "Bad Gateway", &format!("bad response from the server: {}\n", m), &[]).await?;
                    return Ok(());
                }
            };
            let status = parse_status(&rh.first);
            if (100..200).contains(&status) && status != 101 {
                c.inner.write_all(&raw_resp).await?;
                c.inner.flush().await?;
                raw_resp = match u.conn.read_head().await? {
                    Some(h) => h,
                    None => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the server closed after an interim response")),
                };
                continue;
            }
            break (rh, status);
        };

        if status == 101 {
            // protocol switch (WebSocket over plain http): from here on it is a raw tunnel
            c.inner.write_all(&raw_resp).await?;
            c.inner.flush().await?;
            let route = u.route;
            let (mut cs, c_rest) = c.into_parts();
            let (mut us, u_rest) = u.conn.into_parts();
            if !u_rest.is_empty() {
                cs.write_all(&u_rest).await?;
            }
            let flow = Flow { peer, kind: "HTTP-UPGRADE", target: key.clone(), route };
            proxy::relay(st, &mut cs, &mut us, &c_rest, &flow).await;
            return Ok(());
        }

        let resp_body = match response_body(&method, status, &rh.headers) {
            Ok(b) => b,
            Err(m) => {
                log_warn!("[{}] {} {} => {}: {}", peer, method, key, u.route.as_str(), m);
                send_simple(&mut c.inner, 502, "Bad Gateway", &format!("{}\n", m), &[]).await?;
                return Ok(());
            }
        };
        c.inner.write_all(&raw_resp).await?;
        match &resp_body {
            Body::Length(n) => u.conn.copy_exact_to(&mut c.inner, *n).await?,
            Body::Chunked => relay_chunked(&mut u.conn, &mut c.inner).await?,
            Body::UntilClose => {
                u.conn.copy_to_end(&mut c.inner).await?;
            }
            Body::None => {}
        }
        c.inner.flush().await?;

        let req_keep = wants_keepalive(&version, &head.headers);
        let resp_version = rh.first.split_whitespace().next().unwrap_or("HTTP/1.1");
        let resp_keep = wants_keepalive(resp_version, &rh.headers) && resp_body != Body::UntilClose;
        if !(req_keep && resp_keep) {
            let _ = c.inner.shutdown().await;
            return Ok(());
        }
        up = Some(u);
    }
}

async fn connect_tunnel(st: &Arc<Shared>, c: Buffered<TcpStream>, peer: SocketAddr, target: &str) -> io::Result<()> {
    let (host, port) = match parse_authority(target, Some(443)) {
        Ok(x) => x,
        Err(m) => {
            let mut c = c;
            log_warn!("[{}] HTTP CONNECT target '{}' rejected: {}", peer, short(target), m);
            send_simple(&mut c.inner, 400, "Bad Request", &format!("CONNECT target '{}' is not valid: {}\n", short(target), m), &[]).await?;
            return Ok(());
        }
    };
    let (mut client, rest) = c.into_parts();
    let t = Target::new(&host, port);
    let ok: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    let (mut remote, first, route) = if rest.is_empty() && proxy::should_sniff(st, &t) {
        match proxy::sniff_connect(st, &mut client, peer, "CONNECT", &t, ok).await {
            Ok(Some(x)) => x,
            Ok(None) => return Ok(()),
            // the decision and the failure were logged by sniff_connect
            Err(_) => return Ok(()),
        }
    } else {
        match proxy::open_outbound(st, peer, "CONNECT", &t).await {
            Ok(o) => {
                client.write_all(ok).await?;
                client.flush().await?;
                (o.stream, rest, o.route)
            }
            Err(e) => {
                let (code, reason) = status_for(&e);
                send_simple(&mut client, code, reason, &format!("{}\n", e), &[]).await?;
                return Ok(());
            }
        }
    };
    let flow = Flow { peer, kind: "CONNECT", target: t.display(), route };
    proxy::relay(st, &mut client, &mut remote, &first, &flow).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_targets() {
        assert_eq!(parse_absolute_http("http://example.com/a?b=1").unwrap(), ("example.com".into(), 80, "/a?b=1".into()));
        assert_eq!(parse_absolute_http("HTTP://example.com:8080").unwrap(), ("example.com".into(), 8080, "/".into()));
        assert_eq!(parse_absolute_http("http://[::1]:8080/path").unwrap(), ("::1".into(), 8080, "/path".into()));
        assert_eq!(parse_absolute_http("http://[2001:db8::1]/").unwrap(), ("2001:db8::1".into(), 80, "/".into()));
        assert_eq!(parse_absolute_http("http://user:pw@h.example/x#frag").unwrap(), ("h.example".into(), 80, "/x".into()));
        assert_eq!(parse_absolute_http("http://h.example?q=1").unwrap().2, "/?q=1");
        assert!(parse_absolute_http("https://example.com/").is_err());
        assert!(parse_absolute_http("/just/a/path").is_err());
        assert!(parse_absolute_http("ftp://x/").is_err());
        assert!(parse_absolute_http("http://host:99999/").is_err());
    }

    #[test]
    fn framing_rules() {
        let h = |v: &[(&str, &str)]| -> Vec<(String, String)> { v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect() };
        assert_eq!(request_body(&h(&[("Content-Length", "5")])).unwrap(), Body::Length(5));
        assert_eq!(request_body(&h(&[("Transfer-Encoding", "chunked")])).unwrap(), Body::Chunked);
        assert_eq!(request_body(&h(&[])).unwrap(), Body::None);
        assert!(request_body(&h(&[("Content-Length", "x")])).is_err());
        assert_eq!(response_body("GET", 200, &h(&[])).unwrap(), Body::UntilClose);
        assert_eq!(response_body("HEAD", 200, &h(&[("Content-Length", "9")])).unwrap(), Body::None);
        assert_eq!(response_body("GET", 304, &h(&[])).unwrap(), Body::None);
        assert!(wants_keepalive("HTTP/1.1", &h(&[])));
        assert!(!wants_keepalive("HTTP/1.1", &h(&[("Connection", "close")])));
        assert!(!wants_keepalive("HTTP/1.0", &h(&[])));
        assert!(wants_keepalive("HTTP/1.0", &h(&[("Connection", "Keep-Alive")])));
    }

    #[test]
    fn forward_head_drops_proxy_headers_and_keeps_connection() {
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Proxy-Authorization".to_string(), "Basic xx".to_string()),
            ("Proxy-Connection".to_string(), "keep-alive".to_string()),
            ("Connection".to_string(), "keep-alive".to_string()),
        ];
        let out = String::from_utf8(build_forward_head("GET", "/x", "HTTP/1.1", &headers, "example.com", 80)).unwrap();
        assert!(out.starts_with("GET /x HTTP/1.1\r\n"));
        assert!(!out.to_ascii_lowercase().contains("proxy-"));
        assert!(out.contains("Connection: keep-alive"));
        assert!(out.ends_with("\r\n\r\n"));
    }
}
