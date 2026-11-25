//! VPN Share Proxy v3 (Rust).
//!
//! One listening port speaks SOCKS5 (TCP + UDP) and HTTP/HTTPS-CONNECT. Every outgoing
//! connection is sent either out of the modem (Iranian destinations) or through the VPN
//! ("ip net": the Windows system proxy / a system-wide VPN), decided in nanoseconds from
//! in-memory tables that are hot-swapped when lists or settings change.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

macro_rules! log_info {
    ($($a:tt)*) => { $crate::logger::log("INFO", format!($($a)*)) };
}
macro_rules! log_warn {
    ($($a:tt)*) => { $crate::logger::log("WARN", format!($($a)*)) };
}
macro_rules! log_err {
    ($($a:tt)*) => { $crate::logger::log("ERROR", format!($($a)*)) };
}

mod config;
mod dns;
mod httpx;
mod lists;
mod logger;
mod net;
mod proxy;
mod rules;
mod socks;
mod state;
mod udp;
mod ui;
mod update;
mod upstream;
mod util;

#[tokio::main]
async fn main() {
    let paths = config::Paths::discover();
    logger::init(paths.log.clone(), 100);
    std::panic::set_hook(Box::new(|info| {
        log_err!("panic: {}", info);
    }));
    log_info!(
        "VPN Share Proxy v{} starting (folder: {})",
        env!("CARGO_PKG_VERSION"),
        paths.base.display()
    );

    let settings = config::load_or_create(&paths);
    let _ = std::fs::create_dir_all(&paths.data);
    let route_log = paths.data.join("host_routes.txt");
    let stale = net::cleanup_stale_routes(&route_log);
    if stale > 0 {
        log_info!("removed {} host routes left over from a previous run", stale);
    }
    net::init_route_log(route_log);
    let autostart = settings.autostart_proxy;
    let open_ui = settings.open_ui_on_start;
    let st = state::Shared::new(paths, settings);
    state::bootstrap(&st).await;

    let ui_url = ui::start(st.clone()).await;
    if let Some(url) = &ui_url {
        log_info!("settings UI: {}", url);
        println!("VPN Share Proxy settings UI: {}", url);
        if open_ui {
            net::open_url(url);
        }
    } else {
        log_err!("the settings UI could not start (all UI ports are busy); the proxy still works from config.json");
    }

    if autostart {
        match proxy::start(&st).await {
            Ok(addr) => log_info!("proxy started automatically on {}", addr),
            Err(e) => log_err!("automatic proxy start failed: {}", e),
        }
    }

    state::spawn_background(st.clone());

    tokio::select! {
        _ = st.quit.notified() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    proxy::stop(&st).await;
    let removed = tokio::task::spawn_blocking(net::cleanup_host_routes).await.unwrap_or(0);
    if removed > 0 {
        log_info!("removed {} temporary host routes", removed);
    }
    log_info!("bye");
    // give the log writer thread a moment to flush the last lines
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
}
