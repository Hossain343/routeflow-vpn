//! Settings (config.json), paths next to the executable, validation.
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Paths {
    pub base: PathBuf,
    pub data: PathBuf,
    /// downloaded iran-hosted-domains release files live here
    pub assets: PathBuf,
    pub manifest: PathBuf,
    pub config: PathBuf,
    pub router_divert: PathBuf,
    pub vpn_divert: PathBuf,
    pub ripe: PathBuf,
    pub log: PathBuf,
}

impl Paths {
    pub fn discover() -> Paths {
        let base = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        Paths::at(base)
    }

    pub fn at(base: PathBuf) -> Paths {
        let data = base.join("data");
        let assets = data.join("iran-hosted-domains");
        let manifest = data.join("release.json");
        let config = base.join("config.json");
        let router_divert = base.join("router_divert.json");
        let vpn_divert = base.join("vpn_divert.json");
        let ripe = base.join("RIPE_IR.json");
        let log = base.join("vpnshare.log");
        Paths { base, data, assets, manifest, config, router_divert, vpn_divert, ripe, log }
    }
}

/// Everything below has a default, so an old config.json (from the Python version) still loads.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    // --- listening side (clients connect here)
    pub listen_host: String, // "auto" = IP of the real network card
    pub port: u16,
    pub username: String, // empty = no auth
    pub password: String,
    // --- "ip net": where the VPN route goes
    pub upstream: String, // auto | direct | host:port | http://[u:p@]host:port | socks5://[u:p@]host:port
    pub upstream_user: String,
    pub upstream_pass: String,
    // --- modem side
    pub router_dns: String, // "auto" = the modem itself
    pub nic_ip: String,     // "auto" or the IPv4 of the real card
    pub router_ip: String,  // "auto" or the modem IPv4
    // --- lists / rules (iran-hosted-domains)
    pub ads_block: bool,
    pub use_proxy_category: bool,   // domains blocked inside Iran -> VPN
    pub domestic_tld_direct: bool,  // every *.ir -> modem
    pub list_source: String,        // auto | dat | text
    pub release_tag: String,        // latest | a tag like 202610230802
    pub download_all_assets: bool,
    pub update_ripe: bool,          // also refresh RIPE_IR.json (IP ranges) on update
    pub auto_update_hours: u32,     // 0 = never
    // --- behaviour
    pub sniff_sni: bool,
    pub idle_timeout_secs: u64,
    pub log_connections: bool,
    pub autostart_proxy: bool,
    // --- settings UI
    pub ui_port: u16,
    pub ui_token: String,
    pub open_ui_on_start: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            listen_host: "auto".into(),
            port: 1080,
            username: String::new(),
            password: String::new(),
            upstream: "auto".into(),
            upstream_user: String::new(),
            upstream_pass: String::new(),
            router_dns: "auto".into(),
            nic_ip: "auto".into(),
            router_ip: "auto".into(),
            ads_block: false,
            use_proxy_category: true,
            domestic_tld_direct: true,
            list_source: "auto".into(),
            release_tag: "latest".into(),
            download_all_assets: true,
            update_ripe: true,
            auto_update_hours: 0,
            sniff_sni: true,
            idle_timeout_secs: 1800,
            log_connections: true,
            autostart_proxy: false,
            ui_port: 8787,
            ui_token: String::new(),
            open_ui_on_start: true,
        }
    }
}

fn check_auto_or_ipv4(name: &str, v: &str) -> Result<(), String> {
    let t = v.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("auto") || t.parse::<Ipv4Addr>().is_ok() {
        Ok(())
    } else {
        Err(format!("{} must be 'auto' or an IPv4 address (got '{}')", name, v))
    }
}

impl Settings {
    pub fn validate(&self) -> Result<(), String> {
        if self.port == 0 {
            return Err("proxy port must be between 1 and 65535".into());
        }
        if self.ui_port == 0 {
            return Err("UI port must be between 1 and 65535".into());
        }
        if self.ui_port == self.port {
            return Err("the UI port and the proxy port must differ".into());
        }
        let h = self.listen_host.trim();
        if !(h.eq_ignore_ascii_case("auto") || h.parse::<IpAddr>().is_ok()) {
            return Err(format!("listen address must be 'auto' or an IP address (got '{}')", h));
        }
        crate::upstream::parse_upstream_setting(&self.upstream, &self.upstream_user, &self.upstream_pass)?;
        check_auto_or_ipv4("router_dns", &self.router_dns)?;
        check_auto_or_ipv4("nic_ip", &self.nic_ip)?;
        check_auto_or_ipv4("router_ip", &self.router_ip)?;
        if !matches!(self.list_source.as_str(), "auto" | "dat" | "text") {
            return Err("list_source must be auto, dat or text".into());
        }
        let tag = self.release_tag.trim();
        let tag_ok = tag == "latest"
            || (!tag.is_empty()
                && tag.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')));
        if !tag_ok {
            return Err("release tag must be 'latest' or a tag such as 202610230802".into());
        }
        if self.idle_timeout_secs < 10 {
            return Err("idle timeout must be at least 10 seconds".into());
        }
        Ok(())
    }
}

/// Load config.json. A missing file creates it; a broken file is kept as config.json.bad and
/// reported loudly, then defaults are used (never silently).
pub fn load_or_create(paths: &Paths) -> Settings {
    let mut s = match std::fs::read_to_string(&paths.config) {
        Ok(text) => match serde_json::from_str::<Settings>(text.trim_start_matches('\u{feff}')) {
            Ok(s) => s,
            Err(e) => {
                log_err!("config.json is not valid ({}); keeping a copy as config.json.bad and using defaults", e);
                let _ = std::fs::copy(&paths.config, paths.config.with_extension("json.bad"));
                Settings::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            log_info!("no config.json yet; creating one with defaults");
            Settings::default()
        }
        Err(e) => {
            log_err!("cannot read config.json: {}; using defaults", e);
            Settings::default()
        }
    };
    if let Err(e) = s.validate() {
        log_err!("config.json has an invalid value: {}; falling back to defaults for the whole file", e);
        s = Settings::default();
    }
    if s.ui_token.is_empty() {
        s.ui_token = crate::util::hex_encode(&crate::util::random_bytes(16));
    }
    if let Err(e) = save(paths, &s) {
        log_err!("cannot write config.json: {}", e);
    }
    s
}

/// Atomic write: temp file + rename.
pub fn save(paths: &Paths, s: &Settings) -> Result<(), String> {
    let text = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    write_atomic(&paths.config, text.as_bytes())
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("writing {}: {}", tmp.display(), e))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("renaming into {}: {}", path.display(), e))
}

pub const ROUTER_HELP: &str = "Everything listed here ALWAYS goes straight through the modem (real filtered internet), no questions asked. A domain also matches all of its subdomains. 'ips' accepts single IPs and CIDR ranges (for example 5.6.7.0/24).";
pub const VPN_HELP: &str = "Everything listed here ALWAYS goes through the VPN (ip net), no questions asked. A domain also matches all of its subdomains. 'ips' accepts single IPs and CIDR ranges. If something is in both files, router_divert.json wins.";

/// Create the two divert files if they do not exist. Existing files are never touched.
pub fn ensure_divert_templates(paths: &Paths) {
    for (path, help) in [(&paths.router_divert, ROUTER_HELP), (&paths.vpn_divert, VPN_HELP)] {
        if path.exists() {
            continue;
        }
        let v = serde_json::json!({ "_help": help, "domains": [], "ips": [] });
        let text = serde_json::to_string_pretty(&v).unwrap_or_default();
        if let Err(e) = write_atomic(path, text.as_bytes()) {
            log_err!("cannot create {}: {}", path.display(), e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_python_config_still_loads() {
        let s: Settings = serde_json::from_str(
            r#"{"listen_host":"auto","port":5090,"username":"","password":"","upstream":"auto","router_dns":"auto"}"#,
        )
        .unwrap();
        assert_eq!(s.port, 5090);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn validation_catches_bad_values() {
        let mut s = Settings::default();
        s.upstream = "ftp://x:1".into();
        assert!(s.validate().is_err());
        let mut s = Settings::default();
        s.router_dns = "dns.example".into();
        assert!(s.validate().is_err());
        let mut s = Settings::default();
        s.port = s.ui_port;
        assert!(s.validate().is_err());
    }
}
