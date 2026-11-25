//! Small helpers shared by several modules.
use std::io;
use std::net::IpAddr;

pub fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Errors that just mean "the other side went away"; they are not worth a warning line.
pub fn is_benign(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(
        e.kind(),
        UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe | NotConnected
    )
}

/// Parse `host`, `host:port`, `[v6]` or `[v6]:port` (an authority, no scheme, no path).
pub fn parse_authority(s: &str, default_port: Option<u16>) -> Result<(String, u16), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty host".into());
    }
    let (host, port_str): (&str, Option<&str>) = if let Some(rest) = s.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| format!("unterminated IPv6 literal in '{}'", s))?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        if after.is_empty() {
            (host, None)
        } else if let Some(p) = after.strip_prefix(':') {
            (host, Some(p))
        } else {
            return Err(format!("unexpected text after IPv6 literal in '{}'", s));
        }
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) => {
                if h.contains(':') {
                    return Err(format!("IPv6 addresses must be written in [brackets]: '{}'", s));
                }
                (h, Some(p))
            }
            None => (s, None),
        }
    };
    if host.is_empty() {
        return Err(format!("empty host in '{}'", s));
    }
    let port = match port_str {
        Some(p) => p
            .parse::<u16>()
            .map_err(|_| format!("invalid port '{}' in '{}'", p, s))?,
        None => default_port.ok_or_else(|| format!("missing port in '{}'", s))?,
    };
    if port == 0 {
        return Err("port 0 is not valid".into());
    }
    Ok((host.to_string(), port))
}

pub fn fmt_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// lower-case, no brackets, no trailing dot
pub fn normalize_host(h: &str) -> String {
    h.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

pub fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

pub fn is_loopback_name(h: &str) -> bool {
    let h = h.to_ascii_lowercase();
    h == "localhost" || h.ends_with(".localhost")
}

pub fn is_loopback_ip(ip: IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

/// Constant-time-ish comparison for credentials.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

pub fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fallback_random(buf: &mut [u8]) {
    use std::hash::{BuildHasher, Hasher};
    let state = std::collections::hash_map::RandomState::new();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for (i, chunk) in buf.chunks_mut(8).enumerate() {
        let mut h = state.build_hasher();
        h.write_u128(nanos);
        h.write_usize(i);
        let b = h.finish().to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
}

#[cfg(windows)]
pub fn random_bytes(n: usize) -> Vec<u8> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(h: *mut core::ffi::c_void, buf: *mut u8, len: u32, flags: u32) -> i32;
    }
    let mut v = vec![0u8; n];
    // BCRYPT_USE_SYSTEM_PREFERRED_RNG = 2
    let rc = unsafe { BCryptGenRandom(std::ptr::null_mut(), v.as_mut_ptr(), n as u32, 2) };
    if rc != 0 {
        fallback_random(&mut v);
    }
    v
}

#[cfg(not(windows))]
pub fn random_bytes(n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut v = vec![0u8; n];
    let ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut v))
        .is_ok();
    if !ok {
        fallback_random(&mut v);
    }
    v
}

pub fn random_u16() -> u16 {
    let b = random_bytes(2);
    u16::from_le_bytes([b[0], b[1]])
}


/// "2026-10-23 08:02 UTC" (no time-zone database needed)
pub fn fmt_utc(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y0 = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y0 + 1 } else { y0 };
    format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", y, m, d, rem / 3600, (rem % 3600) / 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_variants() {
        assert_eq!(parse_authority("example.com:443", None).unwrap(), ("example.com".into(), 443));
        assert_eq!(parse_authority("example.com", Some(443)).unwrap(), ("example.com".into(), 443));
        assert_eq!(parse_authority("[::1]:8080", None).unwrap(), ("::1".into(), 8080));
        assert_eq!(parse_authority("[2001:db8::1]", Some(80)).unwrap(), ("2001:db8::1".into(), 80));
        assert!(parse_authority("::1:80", None).is_err());
        assert!(parse_authority("host:99999", None).is_err());
        assert!(parse_authority("host", None).is_err());
        assert!(parse_authority("[::1", None).is_err());
        assert!(parse_authority(":80", None).is_err());
    }

    #[test]
    fn utc_formatting() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(fmt_utc(1_698_048_120), "2023-10-23 08:02 UTC");
        assert_eq!(fmt_utc(951_782_400), "2000-02-29 00:00 UTC");
    }

    #[test]
    fn percent_roundtrip() {
        assert_eq!(pct_decode("a%40b%3Ac"), "a@b:c");
        assert_eq!(pct_decode(&pct_encode("p@ss:w/rd ü")), "p@ss:w/rd ü");
    }
}
