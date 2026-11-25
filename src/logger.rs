//! Tiny logger: a ring buffer for the UI (last N lines) plus a rotating log file written by a
//! background thread, so logging never blocks the proxy hot path.
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Mutex, MutexGuard, OnceLock};

const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

struct Logger {
    ring: Mutex<VecDeque<String>>,
    cap: usize,
    tx: Mutex<Option<Sender<String>>>,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn init(path: PathBuf, cap: usize) {
    let (tx, rx) = channel::<String>();
    let logger = Logger {
        ring: Mutex::new(VecDeque::with_capacity(cap + 1)),
        cap,
        tx: Mutex::new(Some(tx)),
    };
    if LOGGER.set(logger).is_err() {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("log-writer".into())
        .spawn(move || writer_thread(path, rx));
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn writer_thread(path: PathBuf, rx: Receiver<String>) {
    let mut file = match open_append(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("cannot open log file {}: {}", path.display(), e);
            for _ in rx.iter() {}
            return;
        }
    };
    let mut size = file.metadata().map(|m| m.len()).unwrap_or(0);
    while let Ok(first) = rx.recv() {
        let mut batch = vec![first];
        while let Ok(more) = rx.try_recv() {
            batch.push(more);
            if batch.len() >= 256 {
                break;
            }
        }
        for line in batch {
            let bytes = line.len() as u64 + 1;
            if size + bytes > MAX_FILE_BYTES {
                let _ = file.flush();
                let _ = std::fs::rename(&path, path.with_extension("log.old"));
                if let Ok(f) = open_append(&path) {
                    file = f;
                    size = 0;
                }
            }
            if writeln!(file, "{}", line).is_ok() {
                size += bytes;
            }
        }
        let _ = file.flush();
    }
}

#[cfg(windows)]
fn now_hms() -> String {
    #[repr(C)]
    struct SystemTime {
        year: u16,
        month: u16,
        dow: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        ms: u16,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetLocalTime(st: *mut SystemTime);
    }
    let mut st = SystemTime { year: 0, month: 0, dow: 0, day: 0, hour: 0, minute: 0, second: 0, ms: 0 };
    unsafe { GetLocalTime(&mut st) };
    format!("{:02}:{:02}:{:02}", st.hour, st.minute, st.second)
}

#[cfg(not(windows))]
fn now_hms() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{:02}:{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60, secs % 60)
}

pub fn log(level: &str, msg: String) {
    let line = format!("{} {:<5} {}", now_hms(), level, msg);
    match LOGGER.get() {
        Some(l) => {
            {
                let mut ring = lock(&l.ring);
                if ring.len() >= l.cap {
                    ring.pop_front();
                }
                ring.push_back(line.clone());
            }
            if let Some(tx) = lock(&l.tx).as_ref() {
                let _ = tx.send(line);
            }
        }
        None => eprintln!("{}", line),
    }
}

/// The most recent `n` lines (what the UI shows).
pub fn tail(n: usize) -> Vec<String> {
    match LOGGER.get() {
        Some(l) => {
            let ring = lock(&l.ring);
            let skip = ring.len().saturating_sub(n);
            ring.iter().skip(skip).cloned().collect()
        }
        None => Vec::new(),
    }
}
