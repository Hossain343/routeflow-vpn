//! Settings UI: a tiny web server on 127.0.0.1 only (browser = the GUI). Every API call needs the
//! secret token from config.json (kept in the page URL printed in the log), and the Host header is
//! checked, so other web sites and other programs cannot drive it.
use crate::config::{self, write_atomic, Settings};
use crate::httpx::{header, parse_head, Buffered};
use crate::lists;
use crate::logger;
use crate::proxy::{self, Target};
use crate::state::{self, Shared};
use crate::update;
use crate::util::{ct_eq, fmt_utc, is_benign, pct_decode};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HTML: &str = include_str!("ui.html");

/// Starts the UI server. Returns the address to open (with the token) or None if no port was free.
pub async fn start(st: Arc<Shared>) -> Option<String> {
    let s = st.settings.load_full();
    let mut bound: Option<TcpListener> = None;
    for p in s.ui_port..s.ui_port.saturating_add(20) {
        if p == s.port {
            continue;
        }
        if let Ok(l) = TcpListener::bind(("127.0.0.1", p)).await {
            bound = Some(l);
            break;
        }
    }
    let listener = bound?;
    let addr = listener.local_addr().ok()?;
    *st.ui_addr.lock().unwrap_or_else(|e| e.into_inner()) = Some(addr);
    let url = format!("http://127.0.0.1:{}/?t={}", addr.port(), s.ui_token);
    let port = addr.port();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((sock, _)) => {
                    let st2 = st.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle(st2, sock, port).await {
                            if !is_benign(&e) {
                                log_warn!("settings UI request failed: {}", e);
                            }
                        }
                    });
                }
                Err(e) => {
                    log_err!("settings UI: accept failed: {}", e);
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
        }
    });
    Some(url)
}

async fn respond(s: &mut TcpStream, code: u16, ctype: &str, body: &[u8]) -> io::Result<()> {
    let reason = match code {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self' 'unsafe-inline'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n",
        code,
        reason,
        ctype,
        body.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(body).await?;
    s.flush().await?;
    let _ = s.shutdown().await;
    Ok(())
}

fn query_param(q: &str, key: &str) -> String {
    for kv in q.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == key {
                return pct_decode(v);
            }
        }
    }
    String::new()
}

async fn handle(st: Arc<Shared>, sock: TcpStream, port: u16) -> io::Result<()> {
    let mut c = Buffered::new(sock);
    let raw = match tokio::time::timeout(Duration::from_secs(10), c.read_head()).await {
        Ok(Ok(Some(h))) => h,
        Ok(Ok(None)) | Err(_) => return Ok(()),
        Ok(Err(e)) => return Err(e),
    };
    let head = match parse_head(&raw) {
        Ok(h) => h,
        Err(m) => return respond(&mut c.inner, 400, "text/plain", m.as_bytes()).await,
    };
    let mut parts = head.first.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    // DNS-rebinding guard: only our own loopback name:port is accepted as Host
    let host_ok = header(&head.headers, "host")
        .map(|h| {
            let h = h.to_ascii_lowercase();
            h == format!("127.0.0.1:{}", port) || h == format!("localhost:{}", port)
        })
        .unwrap_or(false);
    if !host_ok {
        return respond(&mut c.inner, 403, "text/plain", b"forbidden host").await;
    }

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    let clen: usize = header(&head.headers, "content-length").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
    if clen > 1_000_000 {
        return respond(&mut c.inner, 413, "text/plain", b"too large").await;
    }
    let body = if clen > 0 { c.read_exact_vec(clen).await? } else { Vec::new() };
    let token = st.settings.load_full().ui_token.clone();

    if method == "GET" && path == "/" {
        if !ct_eq(query_param(&query, "t").as_bytes(), token.as_bytes()) {
            return respond(
                &mut c.inner,
                403,
                "text/plain; charset=utf-8",
                "Open the address that contains ?t=... (it is printed in vpnshare.log and opened automatically at start).".as_bytes(),
            )
            .await;
        }
        return respond(&mut c.inner, 200, "text/html; charset=utf-8", HTML.as_bytes()).await;
    }
    if path.starts_with("/api/") {
        let given = header(&head.headers, "x-token").unwrap_or("");
        if !ct_eq(given.as_bytes(), token.as_bytes()) {
            return respond(&mut c.inner, 401, "application/json", b"{\"error\":\"missing or wrong token\"}").await;
        }
        let (code, json) = api(&st, &method, &path, &query, &body).await;
        let bytes = serde_json::to_vec(&json).unwrap_or_else(|_| b"{}".to_vec());
        return respond(&mut c.inner, code, "application/json", &bytes).await;
    }
    respond(&mut c.inner, 404, "text/plain", b"not found").await
}

fn divert_target(st: &Shared, which: &str) -> Option<(PathBuf, &'static str)> {
    match which {
        "router" => Some((st.paths.router_divert.clone(), config::ROUTER_HELP)),
        "vpn" => Some((st.paths.vpn_divert.clone(), config::VPN_HELP)),
        _ => None,
    }
}

async fn api(st: &Arc<Shared>, method: &str, path: &str, query: &str, body: &[u8]) -> (u16, serde_json::Value) {
    use serde_json::json;
    match (method, path) {
        ("GET", "/api/state") => (200, state_json(st).await),
        ("GET", "/api/log") => (200, json!({ "lines": logger::tail(100) })),
        ("POST", "/api/settings") => match serde_json::from_slice::<Settings>(body) {
            Ok(s) => match state::apply_settings(st, s).await {
                Ok(notes) => (200, json!({ "ok": true, "notes": notes })),
                Err(e) => (400, json!({ "ok": false, "error": e })),
            },
            Err(e) => (400, json!({ "ok": false, "error": format!("invalid settings: {}", e) })),
        },
        ("POST", "/api/proxy") => {
            let on = serde_json::from_slice::<serde_json::Value>(body)
                .ok()
                .and_then(|v| v.get("on").and_then(|x| x.as_bool()));
            match on {
                Some(true) => match proxy::start(st).await {
                    Ok(a) => (200, json!({ "ok": true, "listen": a.to_string() })),
                    Err(e) => {
                        log_err!("proxy start failed: {}", e);
                        (400, json!({ "ok": false, "error": e }))
                    }
                },
                Some(false) => {
                    proxy::stop(st).await;
                    (200, json!({ "ok": true }))
                }
                None => (400, json!({ "ok": false, "error": "send {\"on\": true|false}" })),
            }
        }
        ("POST", "/api/update") => {
            if st.updating.load(Ordering::SeqCst) {
                (409, json!({ "ok": false, "error": "an update is already running" }))
            } else {
                tokio::spawn(update::run(st.clone()));
                (202, json!({ "ok": true }))
            }
        }
        ("GET", "/api/divert") => match divert_target(st, &query_param(query, "which")) {
            Some((p, help)) => {
                let text = match tokio::fs::read_to_string(&p).await {
                    Ok(t) => t,
                    Err(_) => serde_json::to_string_pretty(&json!({ "_help": help, "domains": [], "ips": [] })).unwrap_or_default(),
                };
                (200, json!({ "text": text }))
            }
            None => (400, json!({ "error": "which must be router or vpn" })),
        },
        ("POST", "/api/divert") => {
            let (p, _) = match divert_target(st, &query_param(query, "which")) {
                Some(x) => x,
                None => return (400, json!({ "ok": false, "error": "which must be router or vpn" })),
            };
            let text = match serde_json::from_slice::<serde_json::Value>(body)
                .ok()
                .and_then(|v| v.get("text").and_then(|x| x.as_str()).map(|s| s.to_string()))
            {
                Some(t) => t,
                None => return (400, json!({ "ok": false, "error": "send {\"text\": \"...\"}" })),
            };
            let warnings = match lists::parse_divert(&text) {
                Ok((_, w)) => w,
                Err(e) => return (400, json!({ "ok": false, "error": e })),
            };
            if let Err(e) = write_atomic(&p, text.as_bytes()) {
                return (400, json!({ "ok": false, "error": e }));
            }
            let _ = state::reload_diverts(st).await;
            (200, json!({ "ok": true, "warnings": warnings }))
        }
        ("POST", "/api/test") => {
            let _ = state::refresh_nic(st).await;
            let (a, b) = tokio::join!(probe(st, false), probe(st, true));
            (200, json!({ "vpn": a, "router": b }))
        }
        ("POST", "/api/nic/refresh") => match state::refresh_nic(st).await {
            Ok(n) => (200, json!({ "ok": true, "ip": n.ip.to_string() })),
            Err(e) => (200, json!({ "ok": false, "error": e })),
        },
        ("POST", "/api/quit") => {
            st.quit.notify_one();
            (200, json!({ "ok": true }))
        }
        _ => (404, json!({ "error": "unknown endpoint" })),
    }
}

/// Public IP seen when leaving through the VPN route (`false`) or the modem (`true`).
async fn probe(st: &Arc<Shared>, via_router: bool) -> String {
    let mut last = String::from("no attempt");
    for (host, path) in [("api.ipify.org", "/"), ("1.1.1.1", "/cdn-cgi/trace")] {
        let t = Target::new(host, 80);
        let conn = if via_router {
            proxy::connect_router(st, &t).await
        } else {
            proxy::connect_vpn_target(st, &t).await
        };
        let mut s = match conn {
            Ok(s) => s,
            Err(e) => {
                last = e.to_string();
                continue;
            }
        };
        let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, host);
        if let Err(e) = s.write_all(req.as_bytes()).await {
            last = e.to_string();
            continue;
        }
        let mut buf = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(10), s.take(8192).read_to_end(&mut buf)).await;
        if let Ok(Err(e)) = &read {
            last = e.to_string();
            continue;
        }
        if buf.is_empty() {
            last = "empty answer".into();
            continue;
        }
        let text = String::from_utf8_lossy(&buf).into_owned();
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").trim().to_string();
        let ip = body
            .lines()
            .find_map(|l| l.strip_prefix("ip=").map(|x| x.trim().to_string()))
            .unwrap_or_else(|| body.chars().take(45).collect());
        if !ip.is_empty() {
            return ip;
        }
        last = "unreadable answer".into();
    }
    format!("failed: {}", last)
}

async fn state_json(st: &Arc<Shared>) -> serde_json::Value {
    use serde_json::json;
    let s = st.settings.load_full();
    let nic = st.nic.load_full();
    let lists = st.lists.load_full();
    let dv = st.diverts.load_full();
    let ir = st.ir.load_full();
    let resolver = st.upstream.load_full();
    let ip_net = resolver.describe().await;
    let running = proxy::is_running(st).await;
    let release = st.release.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let release_json = release.map(|m| {
        json!({
            "tag": m.tag,
            "requested": m.requested,
            "source": m.source,
            "installed_at": fmt_utc(m.installed_at),
            "files": m.files.len(),
            "verified": m.files.iter().filter(|f| f.verified).count(),
        })
    });
    let nic_json = nic.as_ref().map(|n| {
        json!({
            "name": n.name,
            "ip": n.ip.to_string(),
            "index": n.index,
            "gateway": n.gateway.map(|g| g.to_string()),
        })
    });
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "running": running.is_some(),
        "listen": running.map(|a| a.to_string()),
        "nic": nic_json,
        "ip_net": ip_net,
        "lists": {
            "source": lists.info.source,
            "iran": lists.info.iran,
            "ads": lists.info.ads,
            "proxy": lists.info.proxy,
            "notes": lists.info.notes,
        },
        "ranges": ir.len(),
        "diverts": {
            "router_domains": dv.router.domains.len(),
            "router_ranges": dv.router.ips.len(),
            "vpn_domains": dv.vpn.domains.len(),
            "vpn_ranges": dv.vpn.ips.len(),
        },
        "release": release_json,
        "updating": st.updating.load(Ordering::SeqCst),
        "stats": st.stats.json(),
        "dns_cache": st.dns.cached_entries(),
        "uptime_secs": st.started.elapsed().as_secs(),
        "settings": &*s,
    })
}
