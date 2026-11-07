//! Host facts and the heartbeat, from /proc and /etc/os-release (zeros where a platform has no /proc).

use deploy_proto::msg::Heartbeat;

pub struct Facts {
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub kernel: String,
}

fn read(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn os_release() -> String {
    let text = read("/etc/os-release");
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
            .map(|v| v.trim_matches('"').to_string())
            .unwrap_or_default()
    };
    let (id, ver) = (get("ID"), get("VERSION_ID"));
    if id.is_empty() { std::env::consts::OS.to_string() } else { format!("{id} {ver}").trim().to_string() }
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is writable for its whole length; gethostname NUL-terminates within it on success.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return "unknown".into();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

pub fn facts() -> Facts {
    Facts {
        hostname: hostname(),
        os: os_release(),
        arch: std::env::consts::ARCH.to_string(),
        kernel: read("/proc/sys/kernel/osrelease").trim().to_string(),
    }
}

fn meminfo(key: &str, text: &str) -> u64 {
    text.lines()
        .find_map(|l| l.strip_prefix(key).and_then(|v| v.strip_prefix(':')))
        .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        .unwrap_or(0)
        * 1024
}

pub fn heartbeat(containers_running: u64) -> Heartbeat {
    let mem = read("/proc/meminfo");
    let uptime = read("/proc/uptime").split_whitespace().next().and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    let load1 = read("/proc/loadavg").split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let (disk_total, disk_avail) = disk("/");
    Heartbeat {
        uptime_secs: uptime as u64,
        load1,
        mem_total_bytes: meminfo("MemTotal", &mem),
        mem_available_bytes: meminfo("MemAvailable", &mem),
        disk_total_bytes: disk_total,
        disk_avail_bytes: disk_avail,
        containers_running,
    }
}

#[cfg(unix)]
fn disk(path: &str) -> (u64, u64) {
    let Ok(c) = std::ffi::CString::new(path) else { return (0, 0) };
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path and `s` a writable statvfs.
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return (0, 0);
    }
    let f = s.f_frsize as u64;
    (s.f_blocks as u64 * f, s.f_bavail as u64 * f)
}

#[cfg(not(unix))]
fn disk(_path: &str) -> (u64, u64) {
    (0, 0)
}
