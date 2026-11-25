//! The "update IP" button: downloads the bootmortis/iran-hosted-domains release (every asset, or the
//! core files), verifies the published `.sha256` checksums, and only then installs the files and
//! swaps the new in-memory tables in. Also refreshes RIPE_IR.json (Iranian IP ranges), because
//! the domain release contains no IP ranges.
//!
//! Order matters for consistency: download -> verify -> parse the NEW lists from the staging folder
//! -> install files (with rollback) -> manifest -> swap the in-memory tables. A failure at any step
//! leaves both the old files and the old tables untouched.
use crate::config::write_atomic;
use crate::lists;
use crate::state::Shared;
use crate::upstream::{UpKind, UpstreamSpec};
use crate::util::{fmt_utc, hex_encode, pct_encode, unix_secs};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

const REPO: &str = "bootmortis/iran-hosted-domains";
/// Release inspected when this tool was written (127068 domains). Choose it in Settings to pin it.
pub const PINNED_TAG: &str = "202610230802";
/// Files the engine reads. Without the full asset list (GitHub API unreachable) only these are tried.
const CORE: [&str; 4] = ["iran.dat", "domains.txt", "clash_rules_ads.txt", "clash_rules_other.txt"];
const FALLBACK: [&str; 6] = [
    "iran.dat",
    "domains.txt",
    "clash_rules_ads.txt",
    "clash_rules_ads.yaml",
    "clash_rules_other.txt",
    "clash_rules_other.yaml",
];
const RIPE_URLS: [&str; 2] = [
    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
    "https://ftp.ripe.net/ripe/stats/delegated-ripencc-latest",
];
const MAX_ASSET: usize = 300 * 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileMeta {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    /// true = matched the published .sha256 file
    pub verified: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReleaseMeta {
    pub tag: String,
    pub requested: String,
    pub source: String,
    pub installed_at: u64,
    pub files: Vec<FileMeta>,
}

pub fn load_manifest(st: &Arc<Shared>) {
    match std::fs::read_to_string(&st.paths.manifest) {
        Ok(t) => match serde_json::from_str::<ReleaseMeta>(&t) {
            Ok(m) => {
                log_info!("installed list release: {} ({} files, {})", m.tag, m.files.len(), fmt_utc(m.installed_at));
                *st.release.lock().unwrap_or_else(|e| e.into_inner()) = Some(m);
            }
            Err(e) => log_warn!("data/release.json is unreadable ({}); it will be rewritten by the next update", e),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => log_warn!("cannot read data/release.json: {}", e),
    }
}

struct Asset {
    name: String,
    urls: Vec<String>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

fn build_client(up: Option<&UpstreamSpec>) -> Result<reqwest::Client, String> {
    let mut b = reqwest::Client::builder()
        .user_agent(concat!("vpnshare/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(300))
        .no_proxy();
    if let Some(s) = up {
        let scheme = match s.kind {
            UpKind::Socks5 => "socks5h",
            UpKind::Http => "http",
        };
        let auth = match &s.user {
            Some(u) => format!("{}:{}@", pct_encode(u), pct_encode(s.pass.as_deref().unwrap_or(""))),
            None => String::new(),
        };
        let host = if s.host.contains(':') { format!("[{}]", s.host) } else { s.host.clone() };
        let url = format!("{}://{}{}:{}", scheme, auth, host, s.port);
        b = b.proxy(reqwest::Proxy::all(url).map_err(|e| format!("bad upstream for downloads: {}", e))?);
    }
    b.build().map_err(|e| e.to_string())
}

async fn get_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let resp = client.get(url).send().await.map_err(|e| format!("{}: {}", url, e))?;
    if !resp.status().is_success() {
        return Err(format!("{}: HTTP {}", url, resp.status()));
    }
    let b = resp.bytes().await.map_err(|e| format!("{}: {}", url, e))?;
    if b.len() > MAX_ASSET {
        return Err(format!("{}: file is too large ({} bytes)", url, b.len()));
    }
    Ok(b.to_vec())
}

async fn api_assets(client: &reqwest::Client, api: &str) -> Result<(String, Vec<Asset>), String> {
    let resp = client
        .get(api)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("{}: {}", api, e))?;
    if !resp.status().is_success() {
        return Err(format!("{}: HTTP {}", api, resp.status()));
    }
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    let rel: GhRelease = serde_json::from_slice(&bytes).map_err(|e| format!("unexpected GitHub answer: {}", e))?;
    if rel.assets.is_empty() {
        return Err("the release has no assets".into());
    }
    let assets = rel
        .assets
        .into_iter()
        .map(|a| Asset { name: a.name, urls: vec![a.browser_download_url] })
        .collect();
    Ok((rel.tag_name, assets))
}

/// The asset list of the requested release ("latest" or a tag): GitHub API first, direct URLs after.
async fn release_assets(client: &reqwest::Client, requested: &str) -> (String, Vec<Asset>, &'static str) {
    let api = if requested == "latest" {
        format!("https://api.github.com/repos/{}/releases/latest", REPO)
    } else {
        format!("https://api.github.com/repos/{}/releases/tags/{}", REPO, requested)
    };
    match api_assets(client, &api).await {
        Ok((tag, assets)) => (tag, assets, "GitHub release"),
        Err(e) => {
            log_warn!("could not list the release through the GitHub API ({}); trying direct download links for the core files", e);
            let base = if requested == "latest" {
                format!("https://github.com/{}/releases/latest/download", REPO)
            } else {
                format!("https://github.com/{}/releases/download/{}", REPO, requested)
            };
            let mut v = Vec::new();
            for n in FALLBACK {
                for suffix in ["", ".sha256"] {
                    let name = format!("{}{}", n, suffix);
                    let mut urls = vec![format!("{}/{}", base, name)];
                    if requested == "latest" {
                        urls.push(format!("https://cdn.jsdelivr.net/gh/{}@release/{}", REPO, name));
                    }
                    v.push(Asset { name, urls });
                }
            }
            (requested.to_string(), v, "direct links")
        }
    }
}

fn is_core(name: &str) -> bool {
    let base = name.strip_suffix(".sha256").unwrap_or(name);
    CORE.contains(&base)
}

/// First 64-hex token of a `.sha256` file (`<hash>  <file name>`).
pub fn parse_sha256_file(text: &str) -> Option<String> {
    let tok = text.split_whitespace().next()?.trim_start_matches('*').to_ascii_lowercase();
    if tok.len() == 64 && tok.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(tok)
    } else {
        None
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn remove_dir_quiet(p: &Path) {
    if p.exists() {
        if let Err(e) = std::fs::remove_dir_all(p) {
            log_warn!("could not remove the temporary folder {}: {}", p.display(), e);
        }
    }
}

fn rollback(dest: &Path, backup: &Path, moved: &[(String, bool)]) {
    for (n, had_old) in moved.iter().rev() {
        let _ = std::fs::remove_file(dest.join(n));
        if *had_old {
            let _ = std::fs::rename(backup.join(n), dest.join(n));
        }
    }
}

/// Move the verified files into place; on any failure put every old file back.
fn install_files(stage: &Path, dest: &Path, backup: &Path, names: &[String]) -> Result<(), String> {
    std::fs::create_dir_all(dest).map_err(|e| format!("cannot create {}: {}", dest.display(), e))?;
    std::fs::create_dir_all(backup).map_err(|e| format!("cannot create {}: {}", backup.display(), e))?;
    let mut moved: Vec<(String, bool)> = Vec::new();
    for n in names {
        let d = dest.join(n);
        let had_old = d.exists();
        if had_old {
            if let Err(e) = std::fs::rename(&d, backup.join(n)) {
                rollback(dest, backup, &moved);
                return Err(format!("cannot back up {}: {}", d.display(), e));
            }
        }
        if let Err(e) = std::fs::rename(stage.join(n), &d) {
            if had_old {
                let _ = std::fs::rename(backup.join(n), &d);
            }
            rollback(dest, backup, &moved);
            return Err(format!("cannot install {}: {}", d.display(), e));
        }
        moved.push((n.clone(), had_old));
    }
    Ok(())
}

pub async fn run(st: Arc<Shared>) {
    if st.updating.swap(true, Ordering::SeqCst) {
        log_warn!("an update is already running");
        return;
    }
    let res = run_inner(&st).await;
    st.updating.store(false, Ordering::SeqCst);
    match res {
        Ok(()) => log_info!("update finished"),
        Err(e) => log_err!("update failed: {}", e),
    }
}

async fn run_inner(st: &Arc<Shared>) -> Result<(), String> {
    let settings = st.settings.load_full();
    let up = st.upstream.load_full().current().await;
    let client = build_client(up.as_ref())?;
    log_info!(
        "update started (release '{}', downloads {})",
        settings.release_tag,
        up.as_ref().map(|u| format!("through {}", u.describe())).unwrap_or_else(|| "over the normal route".into())
    );

    let lists_res = update_lists(st, &client, &settings.release_tag, settings.download_all_assets).await;
    if let Err(e) = &lists_res {
        log_err!("domain lists were NOT updated (old files and tables are unchanged): {}", e);
    }
    if settings.update_ripe {
        match update_ripe(st, &client).await {
            Ok(n) => log_info!("RIPE_IR.json updated: {} Iranian ranges", n),
            Err(e) => log_err!("RIPE_IR.json was NOT updated (old ranges stay active): {}", e),
        }
    }
    lists_res
}

async fn update_lists(st: &Arc<Shared>, client: &reqwest::Client, requested: &str, all: bool) -> Result<(), String> {
    let (tag, assets, source) = release_assets(client, requested).await;
    let assets: Vec<Asset> = if all { assets } else { assets.into_iter().filter(|a| is_core(&a.name)).collect() };
    log_info!("release {} via {}: {} files to download", tag, source, assets.len());

    let stage = st.paths.data.join(format!(".staging-{}", unix_secs()));
    let backup = st.paths.data.join(format!(".backup-{}", unix_secs()));
    tokio::fs::create_dir_all(&stage).await.map_err(|e| format!("cannot create {}: {}", stage.display(), e))?;

    let res = stage_and_install(st, client, &tag, requested, source, &assets, &stage, &backup).await;
    remove_dir_quiet(&stage);
    remove_dir_quiet(&backup);
    res
}

#[allow(clippy::too_many_arguments)]
async fn stage_and_install(
    st: &Arc<Shared>,
    client: &reqwest::Client,
    tag: &str,
    requested: &str,
    source: &str,
    assets: &[Asset],
    stage: &PathBuf,
    backup: &PathBuf,
) -> Result<(), String> {
    // ---- 1. download everything into the staging folder
    let mut sums: HashMap<String, String> = HashMap::new(); // file name -> published sha256
    let mut staged: Vec<(String, u64, String)> = Vec::new(); // name, size, computed sha256
    for a in assets {
        let mut last_err = String::from("no download link");
        let mut got: Option<Vec<u8>> = None;
        for url in &a.urls {
            match get_bytes(client, url).await {
                Ok(b) => {
                    got = Some(b);
                    break;
                }
                Err(e) => last_err = e,
            }
        }
        let bytes = match got {
            Some(b) => b,
            None => {
                if is_core(&a.name) && !a.name.ends_with(".sha256") && !a.name.ends_with(".yaml") {
                    return Err(format!("core file {} could not be downloaded: {}", a.name, last_err));
                }
                log_warn!("skipped {}: {}", a.name, last_err);
                continue;
            }
        };
        if let Some(base) = a.name.strip_suffix(".sha256") {
            match parse_sha256_file(&String::from_utf8_lossy(&bytes)) {
                Some(h) => {
                    sums.insert(base.to_string(), h);
                }
                None => log_warn!("{} does not contain a SHA-256 hash; {} stays unverified", a.name, base),
            }
        }
        let sha = sha256_hex(&bytes);
        tokio::fs::write(stage.join(&a.name), &bytes)
            .await
            .map_err(|e| format!("cannot write {}: {}", a.name, e))?;
        staged.push((a.name.clone(), bytes.len() as u64, sha));
    }
    if !staged.iter().any(|(n, _, _)| n == "iran.dat" || n == "domains.txt") {
        return Err("the release contains neither iran.dat nor domains.txt".into());
    }

    // ---- 2. verify against the published checksums
    let mut files: Vec<FileMeta> = Vec::new();
    for (name, size, sha) in &staged {
        if name.ends_with(".sha256") {
            continue;
        }
        let verified = match sums.get(name) {
            Some(expected) => {
                if expected != sha {
                    return Err(format!("checksum mismatch for {} (published {}, downloaded {}); nothing was installed", name, expected, sha));
                }
                true
            }
            None => {
                log_warn!("{}: no published checksum, installed unverified", name);
                false
            }
        };
        files.push(FileMeta { name: name.clone(), size: *size, sha256: sha.clone(), verified });
    }
    let verified_count = files.iter().filter(|f| f.verified).count();
    log_info!("checksums: {} of {} files verified", verified_count, files.len());

    // ---- 3. build the NEW tables from the staging folder before touching anything
    let pref = st.settings.load_full().list_source.clone();
    let stage_for_parse = stage.clone();
    let new_lists = tokio::task::spawn_blocking(move || lists::build_listset(&stage_for_parse, &pref))
        .await
        .map_err(|e| format!("list parser crashed: {}", e))??;

    // ---- 4. install the files (rollback on failure), write the manifest
    let names: Vec<String> = staged.iter().map(|(n, _, _)| n.clone()).collect();
    let (s2, d2, b2) = (stage.clone(), st.paths.assets.clone(), backup.clone());
    tokio::task::spawn_blocking(move || install_files(&s2, &d2, &b2, &names))
        .await
        .map_err(|e| format!("installer crashed: {}", e))??;
    let meta = ReleaseMeta {
        tag: tag.to_string(),
        requested: requested.to_string(),
        source: source.to_string(),
        installed_at: unix_secs(),
        files,
    };
    match serde_json::to_string_pretty(&meta) {
        Ok(text) => {
            if let Err(e) = write_atomic(&st.paths.manifest, text.as_bytes()) {
                log_warn!("release.json could not be written: {}", e);
            }
        }
        Err(e) => log_warn!("release.json could not be encoded: {}", e),
    }

    // ---- 5. swap the in-memory tables: files on disk and memory now agree
    let info = new_lists.info.clone();
    st.lists.store(Arc::new(new_lists));
    *st.release.lock().unwrap_or_else(|e| e.into_inner()) = Some(meta);
    log_info!(
        "lists installed: release {} ({}): {} Iranian, {} ads, {} proxy-category domains",
        tag, info.source, info.iran, info.ads, info.proxy
    );
    for n in &info.notes {
        log_info!("lists: {}", n);
    }
    Ok(())
}

// ------------------------------------------------------------------ RIPE (Iranian IP ranges)

fn v4_range_to_cidrs(start: u32, count: u64) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = u64::from(start);
    let end = cur + count;
    while cur < end {
        let align: u64 = if cur == 0 { 1u64 << 32 } else { cur & cur.wrapping_neg() };
        let mut size = align;
        while size > end - cur {
            size >>= 1;
        }
        let prefix = 32 - size.trailing_zeros();
        out.push(format!("{}/{}", Ipv4Addr::from(cur as u32), prefix));
        cur += size;
    }
    out
}

/// RIPE "delegated" statistics -> Iranian IPv4 / IPv6 CIDR lists.
pub fn parse_delegated(text: &str) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for line in text.lines() {
        if !line.contains("|IR|") {
            continue;
        }
        let p: Vec<&str> = line.trim().split('|').collect();
        if p.len() < 7 || p[1] != "IR" || !(p[6] == "allocated" || p[6] == "assigned") {
            continue;
        }
        match p[2] {
            "ipv4" => {
                if let (Ok(a), Ok(n)) = (p[3].parse::<Ipv4Addr>(), p[4].parse::<u64>()) {
                    if n > 0 && n <= (1u64 << 32) {
                        v4.extend(v4_range_to_cidrs(u32::from(a), n));
                    }
                }
            }
            "ipv6" => {
                if p[4].parse::<u8>().is_ok() {
                    v6.push(format!("{}/{}", p[3], p[4]));
                }
            }
            _ => {}
        }
    }
    (v4, v6)
}

async fn update_ripe(st: &Arc<Shared>, client: &reqwest::Client) -> Result<usize, String> {
    let mut last = String::from("no download link");
    for url in RIPE_URLS {
        let bytes = match get_bytes(client, url).await {
            Ok(b) => b,
            Err(e) => {
                last = e;
                continue;
            }
        };
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let (v4, v6) = tokio::task::spawn_blocking(move || parse_delegated(&text))
            .await
            .map_err(|e| format!("RIPE parser crashed: {}", e))?;
        if v4.is_empty() {
            last = format!("{}: the file has no Iranian IPv4 ranges", url);
            continue;
        }
        let json = serde_json::json!({
            "source": url,
            "updated": fmt_utc(unix_secs()),
            "ipv4": v4,
            "ipv6": v6,
        });
        let text = serde_json::to_string(&json).map_err(|e| e.to_string())?;
        let (set, _bad) = lists::parse_ripe(&text)?; // validate before writing
        write_atomic(&st.paths.ripe, text.as_bytes())?;
        let n = set.len();
        st.ir.store(Arc::new(set));
        return Ok(n);
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_file_formats() {
        let h = "a".repeat(64);
        assert_eq!(parse_sha256_file(&format!("{}  domains.txt\n", h)), Some(h.clone()));
        assert_eq!(parse_sha256_file(&format!("{} *iran.dat", h.to_uppercase())), Some(h.clone()));
        assert_eq!(parse_sha256_file("nothex  file"), None);
        assert_eq!(parse_sha256_file(""), None);
    }

    #[test]
    fn sha256_of_known_input() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn ranges_become_cidrs() {
        assert_eq!(v4_range_to_cidrs(u32::from(Ipv4Addr::new(5, 22, 0, 0)), 256), vec!["5.22.0.0/24"]);
        assert_eq!(
            v4_range_to_cidrs(u32::from(Ipv4Addr::new(2, 144, 0, 0)), 786_432),
            vec!["2.144.0.0/13", "2.152.0.0/14"]
        );
        // not aligned: 10.0.0.128 + 384 addresses = /25 + /24
        assert_eq!(
            v4_range_to_cidrs(u32::from(Ipv4Addr::new(10, 0, 0, 128)), 384),
            vec!["10.0.0.128/25", "10.0.1.0/24"]
        );
    }

    #[test]
    fn delegated_file_parsing() {
        let data = "2|ripencc|20261101|9|19830705|20261101|+0100\n\
                    ripencc|*|ipv4|*|9|summary\n\
                    ripencc|IR|ipv4|2.144.0.0|786432|20100412|allocated\n\
                    ripencc|IR|ipv4|9.9.9.0|256|20100412|reserved\n\
                    ripencc|DE|ipv4|3.3.3.0|256|20100412|allocated\n\
                    ripencc|IR|ipv6|2a01:5ec0::|32|20100412|allocated\n";
        let (v4, v6) = parse_delegated(data);
        assert_eq!(v4, vec!["2.144.0.0/13", "2.152.0.0/14"]);
        assert_eq!(v6, vec!["2a01:5ec0::/32"]);
    }

    #[test]
    fn install_rolls_back_on_failure() {
        let root = std::env::temp_dir().join(format!("vpnshare-test-{}", unix_secs()));
        let (stage, dest, backup) = (root.join("s"), root.join("d"), root.join("b"));
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("a.txt"), "old-a").unwrap();
        std::fs::write(stage.join("a.txt"), "new-a").unwrap();
        // b.txt is announced but missing in staging -> the second move fails
        let names = vec!["a.txt".to_string(), "b.txt".to_string()];
        assert!(install_files(&stage, &dest, &backup, &names).is_err());
        assert_eq!(std::fs::read_to_string(dest.join("a.txt")).unwrap(), "old-a");
        assert!(!dest.join("b.txt").exists());
        std::fs::write(stage.join("b.txt"), "new-b").unwrap();
        std::fs::write(stage.join("a.txt"), "new-a").unwrap();
        let _ = std::fs::remove_dir_all(&backup);
        assert!(install_files(&stage, &dest, &backup, &names).is_ok());
        assert_eq!(std::fs::read_to_string(dest.join("a.txt")).unwrap(), "new-a");
        let _ = std::fs::remove_dir_all(&root);
    }
}
