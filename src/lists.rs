//! Parsers for every list format we read: plain / Clash / YAML domain lists, the v2fly-style
//! `iran.dat` (tiny hand-written protobuf reader, no extra dependency), the divert JSON files
//! and RIPE_IR.json.
use crate::rules::{DivertSet, Diverts, DomainSet, IpSet, ListInfo, ListSet};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub enum Entry {
    Suffix(String),
    Full(String),
    Keyword(String),
    Regex,
    Skip,
}

#[derive(Default, Debug, Clone)]
pub struct LoadStats {
    pub loaded: usize,
    pub ignored: usize,
    pub regex: usize,
}

fn clean_domain(d: &str) -> Option<String> {
    let d = d.trim().trim_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return None;
    }
    let bad = d.chars().any(|c| {
        c.is_whitespace() || matches!(c, '/' | ':' | ',' | '*' | '[' | ']' | '@' | '\\' | '"' | '\'')
    });
    if bad || d.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some(d)
}

fn suffix(d: &str) -> Entry {
    clean_domain(d).map(Entry::Suffix).unwrap_or(Entry::Skip)
}
fn full(d: &str) -> Entry {
    clean_domain(d).map(Entry::Full).unwrap_or(Entry::Skip)
}
fn keyword(k: &str) -> Entry {
    let k = k.trim().to_ascii_lowercase();
    if k.is_empty() {
        Entry::Skip
    } else {
        Entry::Keyword(k)
    }
}

/// One line of any supported text format:
///   `example.com`  `+.example.com`  `*.example.com`  `.example.com`   -> suffix
///   `domain:x` `full:x` `keyword:x` `regexp:x`                         (v2fly)
///   `DOMAIN-SUFFIX,x` `DOMAIN,x` `DOMAIN-KEYWORD,x`                    (Clash classical)
///   `- 'x'` (YAML payload items), `# comments`, `payload:` header
/// A bare name is treated as a suffix (it also covers subdomains).
pub fn parse_domain_line(raw: &str) -> Entry {
    let mut line = raw.trim().trim_start_matches('\u{feff}').trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with("//") || line.starts_with(';') {
        return Entry::Skip;
    }
    if let Some(i) = line.find(" #") {
        line = line[..i].trim();
    }
    if line.eq_ignore_ascii_case("payload:") {
        return Entry::Skip;
    }
    if let Some(rest) = line.strip_prefix("- ") {
        line = rest.trim();
    }
    line = line.trim_matches(|c: char| c == '\'' || c == '"').trim();
    if line.is_empty() {
        return Entry::Skip;
    }
    if let Some((ty, rest)) = line.split_once(',') {
        let val = rest.split(',').next().unwrap_or("").trim();
        return match ty.trim().to_ascii_uppercase().as_str() {
            "DOMAIN-SUFFIX" => suffix(val),
            "DOMAIN" => full(val),
            "DOMAIN-KEYWORD" => keyword(val),
            "DOMAIN-REGEX" => Entry::Regex,
            _ => Entry::Skip,
        };
    }
    let tok = line.split_whitespace().next().unwrap_or("");
    let lower = tok.to_ascii_lowercase();
    if lower.starts_with("include:") {
        return Entry::Skip;
    }
    if let Some(v) = lower.strip_prefix("full:") {
        return full(v);
    }
    if let Some(v) = lower.strip_prefix("domain:") {
        return suffix(v);
    }
    if let Some(v) = lower.strip_prefix("keyword:") {
        return keyword(v);
    }
    if lower.starts_with("regexp:") {
        return Entry::Regex;
    }
    let t = lower
        .strip_prefix("+.")
        .or_else(|| lower.strip_prefix("*."))
        .or_else(|| lower.strip_prefix('.'))
        .unwrap_or(lower.as_str());
    suffix(t)
}

pub fn add_entry(set: &mut DomainSet, e: Entry, st: &mut LoadStats) {
    match e {
        Entry::Suffix(d) => {
            set.add_suffix(&d);
            st.loaded += 1;
        }
        Entry::Full(d) => {
            set.add_full(&d);
            st.loaded += 1;
        }
        Entry::Keyword(k) => {
            if set.add_keyword(&k) {
                st.loaded += 1;
            } else {
                st.ignored += 1;
            }
        }
        Entry::Regex => st.regex += 1,
        Entry::Skip => st.ignored += 1,
    }
}

pub fn load_text_domains(path: &Path, set: &mut DomainSet) -> Result<LoadStats, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    let text = String::from_utf8(bytes).map_err(|e| format!("{}: not valid UTF-8 ({})", path.display(), e))?;
    let mut st = LoadStats::default();
    for line in text.lines() {
        add_entry(set, parse_domain_line(line), &mut st);
    }
    Ok(st)
}

// ----------------------------------------------------------------- iran.dat (protobuf)

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, p: 0 }
    }
    fn eof(&self) -> bool {
        self.p >= self.b.len()
    }
    fn varint(&mut self) -> Result<u64, String> {
        let mut shift = 0u32;
        let mut v = 0u64;
        loop {
            if self.p >= self.b.len() {
                return Err("truncated varint".into());
            }
            if shift >= 64 {
                return Err("varint too long".into());
            }
            let byte = self.b[self.p];
            self.p += 1;
            v |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
        }
    }
    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.varint()? as usize;
        let end = self.p.checked_add(len).ok_or_else(|| "length overflow".to_string())?;
        if end > self.b.len() {
            return Err("truncated field".into());
        }
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }
    fn advance(&mut self, n: usize) -> Result<(), String> {
        if self.p + n > self.b.len() {
            return Err("truncated fixed-size field".into());
        }
        self.p += n;
        Ok(())
    }
    fn skip(&mut self, wire: u64) -> Result<(), String> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => self.advance(8)?,
            2 => {
                self.bytes()?;
            }
            5 => self.advance(4)?,
            w => return Err(format!("unsupported protobuf wire type {}", w)),
        }
        Ok(())
    }
}

pub struct DatSite {
    pub code: String,
    /// (type, value): 0 keyword, 1 regex, 2 domain (suffix), 3 full
    pub domains: Vec<(u8, String)>,
}

/// GeoSiteList { repeated GeoSite entry = 1 }, GeoSite { string country_code = 1; repeated Domain domain = 2 },
/// Domain { Type type = 1; string value = 2; repeated Attribute attribute = 3 }
pub fn parse_geosite(data: &[u8], wanted: &[&str]) -> Result<Vec<DatSite>, String> {
    let mut out = Vec::new();
    let mut r = Reader::new(data);
    while !r.eof() {
        let tag = r.varint()?;
        let (field, wire) = (tag >> 3, tag & 7);
        if field == 1 && wire == 2 {
            let body = r.bytes()?;
            if let Some(site) = parse_site(body, wanted)? {
                out.push(site);
            }
        } else {
            r.skip(wire)?;
        }
    }
    Ok(out)
}

fn parse_site(body: &[u8], wanted: &[&str]) -> Result<Option<DatSite>, String> {
    let mut code = String::new();
    let mut raw_domains: Vec<&[u8]> = Vec::new();
    let mut r = Reader::new(body);
    while !r.eof() {
        let tag = r.varint()?;
        let (field, wire) = (tag >> 3, tag & 7);
        match (field, wire) {
            (1, 2) => {
                code = String::from_utf8_lossy(r.bytes()?).to_ascii_lowercase();
            }
            (2, 2) => raw_domains.push(r.bytes()?),
            _ => r.skip(wire)?,
        }
    }
    if !wanted.iter().any(|w| *w == code) {
        return Ok(None);
    }
    let mut domains = Vec::with_capacity(raw_domains.len());
    for d in raw_domains {
        let mut dr = Reader::new(d);
        let mut ty = 0u8;
        let mut val = String::new();
        while !dr.eof() {
            let tag = dr.varint()?;
            let (field, wire) = (tag >> 3, tag & 7);
            match (field, wire) {
                (1, 0) => ty = dr.varint()? as u8,
                (2, 2) => val = String::from_utf8_lossy(dr.bytes()?).into_owned(),
                _ => dr.skip(wire)?,
            }
        }
        if !val.is_empty() {
            domains.push((ty, val));
        }
    }
    Ok(Some(DatSite { code, domains }))
}

fn dat_entry(ty: u8, val: &str) -> Entry {
    match ty {
        2 => suffix(val),
        3 => full(val),
        0 => keyword(val),
        1 => Entry::Regex,
        _ => Entry::Skip,
    }
}

/// Build the domain tables from the downloaded release folder.
/// `pref`: "auto" (iran.dat, falling back to the text files), "dat" or "text".
pub fn build_listset(dir: &Path, pref: &str) -> Result<ListSet, String> {
    let mut notes: Vec<String> = Vec::new();
    let dat = dir.join("iran.dat");

    if pref != "text" && dat.exists() {
        let parsed = std::fs::read(&dat)
            .map_err(|e| format!("iran.dat: {}", e))
            .and_then(|b| parse_geosite(&b, &["all", "ir", "other", "tld-ir", "ads", "proxy"]).map_err(|e| format!("iran.dat: {}", e)));
        match parsed {
            Ok(sites) => {
                let mut iran = DomainSet::default();
                let mut ads = DomainSet::default();
                let mut proxy = DomainSet::default();
                let mut stats = LoadStats::default();
                for s in sites {
                    let n = s.domains.len();
                    let target = match s.code.as_str() {
                        "ads" => &mut ads,
                        "proxy" => &mut proxy,
                        _ => &mut iran,
                    };
                    for (ty, val) in s.domains {
                        add_entry(target, dat_entry(ty, &val), &mut stats);
                    }
                    notes.push(format!("category {}: {} entries", s.code, n));
                }
                if iran.len() > 0 {
                    if stats.regex > 0 {
                        notes.push(format!("{} regexp rules in iran.dat are not supported and were skipped", stats.regex));
                    }
                    let info = ListInfo {
                        source: "iran.dat".into(),
                        iran: iran.len(),
                        ads: ads.len(),
                        proxy: proxy.len(),
                        regex_skipped: stats.regex,
                        notes,
                    };
                    return Ok(ListSet { iran, ads, proxy, info });
                }
                notes.push("iran.dat contained no Iranian categories".into());
            }
            Err(e) => notes.push(e),
        }
        if pref == "dat" {
            return Err(format!("source 'dat' requested but unusable: {}", notes.join("; ")));
        }
    } else if pref == "dat" {
        return Err("source 'dat' requested but iran.dat is not downloaded yet".into());
    }

    // text fallback: domains.txt (all Iranian domains) or clash_rules_other.txt, plus the ads list
    let mut iran = DomainSet::default();
    let mut ads = DomainSet::default();
    let mut stats = LoadStats::default();
    let domains_txt = dir.join("domains.txt");
    let other_txt = dir.join("clash_rules_other.txt");
    let ads_txt = dir.join("clash_rules_ads.txt");
    let used = if domains_txt.exists() {
        let st = load_text_domains(&domains_txt, &mut iran)?;
        stats.regex += st.regex;
        "domains.txt"
    } else if other_txt.exists() {
        let st = load_text_domains(&other_txt, &mut iran)?;
        stats.regex += st.regex;
        notes.push("domains.txt missing: using clash_rules_other.txt (non-.ir only; the *.ir rule covers the rest)".into());
        "clash_rules_other.txt"
    } else {
        return Err(format!(
            "no list files in {} - press the update button first",
            dir.display()
        ));
    };
    if ads_txt.exists() {
        let st = load_text_domains(&ads_txt, &mut ads)?;
        stats.regex += st.regex;
    } else {
        notes.push("clash_rules_ads.txt missing: ads block has no data".into());
    }
    notes.push("text lists have no 'proxy' category".into());
    let info = ListInfo {
        source: used.into(),
        iran: iran.len(),
        ads: ads.len(),
        proxy: 0,
        regex_skipped: stats.regex,
        notes,
    };
    Ok(ListSet { iran, ads, proxy: DomainSet::default(), info })
}

// ----------------------------------------------------------------- divert files, RIPE

#[derive(Deserialize, Default)]
struct DivertFile {
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    ips: Vec<String>,
}

/// Parse the text of router_divert.json / vpn_divert.json. Returns the tables and a list of
/// warnings for entries that could not be understood (shown in the log / UI, never dropped silently).
pub fn parse_divert(text: &str) -> Result<(DivertSet, Vec<String>), String> {
    let f: DivertFile = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|e| format!("invalid JSON: {}", e))?;
    let mut set = DivertSet::default();
    let mut warn = Vec::new();
    for e in f.ips.iter().chain(f.domains.iter()) {
        let e = e.trim();
        if e.is_empty() {
            continue;
        }
        if set.ips.add_cidr(e).is_ok() {
            continue;
        }
        match parse_domain_line(e) {
            Entry::Suffix(d) => set.domains.add_suffix(&d),
            Entry::Full(d) => set.domains.add_full(&d),
            Entry::Keyword(k) => {
                if !set.domains.add_keyword(&k) {
                    warn.push(format!("too many keywords, ignored '{}'", e));
                }
            }
            _ => warn.push(format!("ignored entry '{}'", e)),
        }
    }
    set.ips.finish();
    Ok((set, warn))
}

fn load_divert_file(path: &Path) -> Result<(DivertSet, Vec<String>), String> {
    match std::fs::read_to_string(path) {
        Ok(t) => parse_divert(&t).map_err(|e| format!("{}: {}", path.display(), e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((DivertSet::default(), Vec::new())),
        Err(e) => Err(format!("{}: {}", path.display(), e)),
    }
}

pub fn load_diverts(router: &Path, vpn: &Path) -> Result<(Diverts, Vec<String>), String> {
    let (r, mut w1) = load_divert_file(router)?;
    let (v, w2) = load_divert_file(vpn)?;
    w1.extend(w2);
    Ok((Diverts { router: r, vpn: v }, w1))
}

#[derive(Deserialize, Default)]
struct RipeFile {
    #[serde(default)]
    ipv4: Vec<String>,
    #[serde(default)]
    ipv6: Vec<String>,
}

/// RIPE_IR.json -> IpSet. Returns the number of entries that could not be parsed as well.
pub fn parse_ripe(text: &str) -> Result<(IpSet, usize), String> {
    let f: RipeFile = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {}", e))?;
    let mut set = IpSet::default();
    let mut bad = 0usize;
    for c in f.ipv4.iter().chain(f.ipv6.iter()) {
        if set.add_cidr(c).is_err() {
            bad += 1;
        }
    }
    set.finish();
    Ok((set, bad))
}

pub fn load_ripe(path: &Path) -> Result<(IpSet, usize), String> {
    match std::fs::read_to_string(path) {
        Ok(t) => parse_ripe(&t).map_err(|e| format!("{}: {}", path.display(), e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((IpSet::default(), 0)),
        Err(e) => Err(format!("{}: {}", path.display(), e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_formats() {
        assert_eq!(parse_domain_line("example.com"), Entry::Suffix("example.com".into()));
        assert_eq!(parse_domain_line("+.Example.COM"), Entry::Suffix("example.com".into()));
        assert_eq!(parse_domain_line("*.example.com"), Entry::Suffix("example.com".into()));
        assert_eq!(parse_domain_line(".example.com"), Entry::Suffix("example.com".into()));
        assert_eq!(parse_domain_line("full:a.example.com"), Entry::Full("a.example.com".into()));
        assert_eq!(parse_domain_line("domain:example.com @ads"), Entry::Suffix("example.com".into()));
        assert_eq!(parse_domain_line("keyword:shop"), Entry::Keyword("shop".into()));
        assert_eq!(parse_domain_line("regexp:^a.*$"), Entry::Regex);
        assert_eq!(parse_domain_line("DOMAIN-SUFFIX,example.com,DIRECT"), Entry::Suffix("example.com".into()));
        assert_eq!(parse_domain_line("DOMAIN,exact.example.com"), Entry::Full("exact.example.com".into()));
        assert_eq!(parse_domain_line("  - '+.example.ir'"), Entry::Suffix("example.ir".into()));
        assert_eq!(parse_domain_line("payload:"), Entry::Skip);
        assert_eq!(parse_domain_line("# comment"), Entry::Skip);
        assert_eq!(parse_domain_line("1.2.3.4"), Entry::Skip);
        assert_eq!(parse_domain_line("IP-CIDR,1.2.3.0/24"), Entry::Skip);
        assert_eq!(parse_domain_line("example.com # trailing"), Entry::Suffix("example.com".into()));
    }

    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = vec![];
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    }
    fn field_bytes(field: u64, payload: &[u8]) -> Vec<u8> {
        let mut o = varint((field << 3) | 2);
        o.extend(varint(payload.len() as u64));
        o.extend_from_slice(payload);
        o
    }

    #[test]
    fn geosite_roundtrip() {
        let mut d1 = varint((1 << 3) | 0);
        d1.extend(varint(2)); // type = domain
        d1.extend(field_bytes(2, b"digikala.com"));
        let mut d2 = varint((1 << 3) | 0);
        d2.extend(varint(3)); // type = full
        d2.extend(field_bytes(2, b"exact.example.ir"));
        let mut site = field_bytes(1, b"ALL");
        site.extend(field_bytes(2, &d1));
        site.extend(field_bytes(2, &d2));
        let mut other = field_bytes(1, b"UNWANTED");
        other.extend(field_bytes(2, &d1));
        let mut file = field_bytes(1, &site);
        file.extend(field_bytes(1, &other));
        let sites = parse_geosite(&file, &["all", "ads"]).unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].code, "all");
        assert_eq!(sites[0].domains, vec![(2, "digikala.com".to_string()), (3, "exact.example.ir".to_string())]);
        assert!(parse_geosite(&file[..file.len() - 3], &["all"]).is_err());
    }

    #[test]
    fn divert_parsing_reports_bad_entries() {
        let (set, warn) = parse_divert(
            r#"{"_help":"x","domains":["Bank.com","full:a.b.c","*.pay.ir","http://bad url"],"ips":["10.1.2.3","5.6.7.0/24"]}"#,
        )
        .unwrap();
        assert!(set.domains.matches("www.bank.com"));
        assert!(set.domains.matches("a.b.c"));
        assert!(set.domains.matches("x.pay.ir"));
        assert!(set.ips.contains("5.6.7.9".parse().unwrap()));
        assert_eq!(warn.len(), 1);
        assert!(parse_divert("{ not json").is_err());
    }
}
