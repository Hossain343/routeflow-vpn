//! Shared application state. Rules, settings, NIC and upstream live behind `ArcSwap`, so the proxy
//! reads them lock-free per connection and a reload swaps a whole consistent snapshot atomically.
use crate::config::{self, Paths, Settings};
use crate::dns::ModemDns;
use crate::lists;
use crate::net::{self, NicInfo};
use crate::proxy::{self, ProxyHandle};
use crate::rules::{Diverts, Flags, IpSet, ListInfo, ListSet};
use crate::update::{self, ReleaseMeta};
use crate::upstream::{self, UpstreamMode, UpstreamResolver};
use arc_swap::{ArcSwap, ArcSwapOption};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{Mutex as AsyncMutex, Notify};

pub struct Stats {
    pub active: AtomicU64,
    pub total: AtomicU64,
    pub router: AtomicU64,
    pub vpn: AtomicU64,
    pub blocked: AtomicU64,
    pub failed: AtomicU64,
    pub up: AtomicU64,
    pub down: AtomicU64,
}

impl Stats {
    fn new() -> Stats {
        Stats {
            active: AtomicU64::new(0),
            total: AtomicU64::new(0),
            router: AtomicU64::new(0),
            vpn: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
        }
    }
    pub fn json(&self) -> serde_json::Value {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        serde_json::json!({
            "active": g(&self.active), "total": g(&self.total), "router": g(&self.router),
            "vpn": g(&self.vpn), "blocked": g(&self.blocked), "failed": g(&self.failed),
            "bytes_up": g(&self.up), "bytes_down": g(&self.down),
        })
    }
}

pub struct Shared {
    pub paths: Paths,
    pub settings: ArcSwap<Settings>,
    pub lists: ArcSwap<ListSet>,
    pub diverts: ArcSwap<Diverts>,
    pub ir: ArcSwap<IpSet>,
    pub upstream: ArcSwap<UpstreamResolver>,
    pub nic: ArcSwapOption<NicInfo>,
    pub dns: ModemDns,
    pub stats: Stats,
    pub proxy: AsyncMutex<Option<ProxyHandle>>,
    pub updating: AtomicBool,
    pub release: Mutex<Option<ReleaseMeta>>,
    pub ui_addr: Mutex<Option<SocketAddr>>,
    pub quit: Notify,
    pub started: Instant,
}

pub fn flags_of(s: &Settings) -> Flags {
    Flags {
        ads_block: s.ads_block,
        use_proxy_category: s.use_proxy_category,
        domestic_tld_direct: s.domestic_tld_direct,
    }
}

impl Shared {
    pub fn new(paths: Paths, settings: Settings) -> Arc<Shared> {
        Arc::new(Shared {
            paths,
            settings: ArcSwap::from_pointee(settings),
            lists: ArcSwap::from_pointee(ListSet::default()),
            diverts: ArcSwap::from_pointee(Diverts::default()),
            ir: ArcSwap::from_pointee(IpSet::default()),
            upstream: ArcSwap::from_pointee(UpstreamResolver::new(UpstreamMode::Auto, 0, Vec::new())),
            nic: ArcSwapOption::empty(),
            dns: ModemDns::new(),
            stats: Stats::new(),
            proxy: AsyncMutex::new(None),
            updating: AtomicBool::new(false),
            release: Mutex::new(None),
            ui_addr: Mutex::new(None),
            quit: Notify::new(),
            started: Instant::now(),
        })
    }
}

/// Load everything from disk once at startup. Failures are logged and the app still starts
/// (with empty lists, the *.ir rule and the divert files keep working).
pub async fn bootstrap(st: &Arc<Shared>) {
    config::ensure_divert_templates(&st.paths);
    let _ = reload_diverts(st).await;
    let _ = reload_ir(st).await;
    let _ = refresh_nic(st).await;
    rebuild_upstream(st);
    update::load_manifest(st);
    if reload_lists(st).await.is_err() {
        log_warn!("no domain lists yet: press the update button in the settings UI (the *.ir rule and the divert files work meanwhile)");
    }
}

pub async fn reload_lists(st: &Arc<Shared>) -> Result<ListInfo, String> {
    let dir = st.paths.assets.clone();
    let pref = st.settings.load_full().list_source.clone();
    let res = tokio::task::spawn_blocking(move || lists::build_listset(&dir, &pref))
        .await
        .map_err(|e| format!("list loader crashed: {}", e))?;
    match res {
        Ok(ls) => {
            let info = ls.info.clone();
            log_info!(
                "lists loaded from {}: {} Iranian, {} ads, {} proxy-category domains",
                info.source, info.iran, info.ads, info.proxy
            );
            for n in &info.notes {
                log_info!("lists: {}", n);
            }
            st.lists.store(Arc::new(ls));
            Ok(info)
        }
        Err(e) => {
            log_err!("lists not loaded (previous lists stay active): {}", e);
            Err(e)
        }
    }
}

pub async fn reload_diverts(st: &Arc<Shared>) -> Result<(), String> {
    let r = st.paths.router_divert.clone();
    let v = st.paths.vpn_divert.clone();
    let res = tokio::task::spawn_blocking(move || lists::load_diverts(&r, &v))
        .await
        .map_err(|e| format!("divert loader crashed: {}", e))?;
    match res {
        Ok((d, warns)) => {
            for w in &warns {
                log_warn!("divert files: {}", w);
            }
            log_info!(
                "divert files loaded: router {} domains + {} ranges, vpn {} domains + {} ranges",
                d.router.domains.len(), d.router.ips.len(), d.vpn.domains.len(), d.vpn.ips.len()
            );
            st.diverts.store(Arc::new(d));
            Ok(())
        }
        Err(e) => {
            log_err!("divert files not reloaded (the previous rules stay active): {}", e);
            Err(e)
        }
    }
}

pub async fn reload_ir(st: &Arc<Shared>) -> Result<usize, String> {
    let p = st.paths.ripe.clone();
    let res = tokio::task::spawn_blocking(move || lists::load_ripe(&p))
        .await
        .map_err(|e| format!("RIPE loader crashed: {}", e))?;
    match res {
        Ok((set, bad)) => {
            if bad > 0 {
                log_warn!("RIPE_IR.json: {} entries could not be parsed", bad);
            }
            let n = set.len();
            if n == 0 {
                log_warn!("RIPE_IR.json is missing or empty: Iranian IP addresses are only recognised through the divert files (press update)");
            } else {
                log_info!("RIPE_IR.json loaded: {} merged Iranian ranges", n);
            }
            st.ir.store(Arc::new(set));
            Ok(n)
        }
        Err(e) => {
            log_err!("RIPE_IR.json not reloaded (the previous ranges stay active): {}", e);
            Err(e)
        }
    }
}

pub async fn refresh_nic(st: &Arc<Shared>) -> Result<NicInfo, String> {
    let s = st.settings.load_full();
    match net::detect_nic(&s.nic_ip, &s.router_ip).await {
        Ok(n) => {
            log_info!(
                "real network card: {} ({}), index {}, modem {}",
                n.name,
                n.ip,
                n.index,
                n.gateway.map(|g| g.to_string()).unwrap_or_else(|| "unknown".into())
            );
            st.nic.store(Some(Arc::new(n.clone())));
            st.dns.clear();
            Ok(n)
        }
        Err(e) => {
            log_err!("cannot detect the real network card: {}", e);
            st.nic.store(None);
            Err(e)
        }
    }
}

pub fn rebuild_upstream(st: &Arc<Shared>) {
    let s = st.settings.load_full();
    let mode = match upstream::parse_upstream_setting(&s.upstream, &s.upstream_user, &s.upstream_pass) {
        Ok(m) => m,
        Err(e) => {
            log_err!("upstream setting ignored ({}); using auto", e);
            UpstreamMode::Auto
        }
    };
    let mut hosts: Vec<String> = Vec::new();
    if let Some(n) = st.nic.load_full() {
        hosts.push(n.ip.to_string());
    }
    if !s.listen_host.eq_ignore_ascii_case("auto") {
        hosts.push(s.listen_host.clone());
    }
    st.upstream.store(Arc::new(UpstreamResolver::new(mode, s.port, hosts)));
}

/// Validate, persist and apply new settings to the running engine. Rules, auth, upstream and the
/// divert tables take effect for the next connection; a changed listen address/port restarts the
/// listener. Connections that are already open keep the route they were given.
pub async fn apply_settings(st: &Arc<Shared>, mut new: Settings) -> Result<Vec<String>, String> {
    new.validate()?;
    let old = st.settings.load_full();
    if new.ui_token.trim().is_empty() {
        new.ui_token = old.ui_token.clone();
    }
    config::save(&st.paths, &new)?;
    st.settings.store(Arc::new(new.clone()));

    let mut notes: Vec<String> = Vec::new();
    let nic_before = st.nic.load_full().map(|n| n.ip);
    if old.nic_ip != new.nic_ip || old.router_ip != new.router_ip {
        match refresh_nic(st).await {
            Ok(_) => notes.push("network card detected again".to_string()),
            Err(e) => notes.push(format!("network card: {}", e)),
        }
    }
    let nic_after = st.nic.load_full().map(|n| n.ip);
    if old.router_dns != new.router_dns {
        st.dns.clear();
    }
    rebuild_upstream(st);
    if old.list_source != new.list_source {
        match reload_lists(st).await {
            Ok(i) => notes.push(format!("lists reloaded from {}", i.source)),
            Err(e) => notes.push(format!("lists: {}", e)),
        }
    }
    let listen_changed = old.listen_host != new.listen_host
        || old.port != new.port
        || (new.listen_host.eq_ignore_ascii_case("auto") && nic_before != nic_after);
    if listen_changed && proxy::is_running(st).await.is_some() {
        proxy::stop(st).await;
        match proxy::start(st).await {
            Ok(a) => notes.push(format!("proxy restarted on {}", a)),
            Err(e) => return Err(format!("settings were saved, but the proxy could not restart: {}", e)),
        }
    }
    notes.push("new login, upstream and rules apply to new connections right away; connections already open finish on their old route".to_string());
    log_info!("settings applied");
    Ok(notes)
}

fn mtime(p: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// File watcher (hot reload of manual edits), automatic list updates, DNS cache clean-up.
pub fn spawn_background(st: Arc<Shared>) {
    let w = st.clone();
    tokio::spawn(async move {
        let mut last = [mtime(&w.paths.router_divert), mtime(&w.paths.vpn_divert), mtime(&w.paths.ripe)];
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        loop {
            tick.tick().await;
            let now = [mtime(&w.paths.router_divert), mtime(&w.paths.vpn_divert), mtime(&w.paths.ripe)];
            if now[0] != last[0] || now[1] != last[1] {
                log_info!("divert file changed on disk: reloading");
                let _ = reload_diverts(&w).await;
            }
            if now[2] != last[2] {
                log_info!("RIPE_IR.json changed on disk: reloading");
                let _ = reload_ir(&w).await;
            }
            last = now;
        }
    });

    let g = st.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            g.dns.gc();
        }
    });

    let u = st.clone();
    tokio::spawn(async move {
        let mut last_try: Option<Instant> = None;
        let mut tick = tokio::time::interval(Duration::from_secs(600));
        loop {
            tick.tick().await;
            let hours = u.settings.load_full().auto_update_hours;
            if hours == 0 || u.updating.load(Ordering::SeqCst) {
                continue;
            }
            if let Some(t) = last_try {
                if t.elapsed() < Duration::from_secs(3600) {
                    continue;
                }
            }
            let due = match u.release.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                Some(m) => crate::util::unix_secs().saturating_sub(m.installed_at) >= u64::from(hours) * 3600,
                None => true,
            };
            if due {
                last_try = Some(Instant::now());
                log_info!("automatic update starting");
                update::run(u.clone()).await;
            }
        }
    });
}
