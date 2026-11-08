//! Registry hosts and credentials, shared by the control plane and the agent so both match images to credentials
//! with one rule: a credential is for one normalized host ([`normalize`]), an image is on the host [`image_host`]
//! finds, and Docker Hub is `docker.io` under all its aliases. Docker configs written for cosign, SBOM lookups and
//! buildx key each credential by [`config_key`], the key Docker clients look a registry up under.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::msg::RegistryAuth;

/// Docker Hub's host for matching.
pub const DOCKER_HUB: &str = "docker.io";
/// The key Docker clients look Docker Hub up under in a Docker config.
pub const DOCKER_HUB_KEY: &str = "https://index.docker.io/v1/";
/// Every name of Docker Hub.
const DOCKER_HUB_ALIASES: [&str; 5] =
    ["docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com", "hub.docker.com"];

const PATH_ERROR: &str =
    "a registry host name with an optional port, without a path (credentials are matched by host, not by namespace)";
const LOCAL_ERROR: &str =
    "registries at IP addresses or on this machine are not supported; use the registry's public host name";

/// `docker.io` for a Docker Hub alias, the host otherwise.
fn alias(host: &str) -> &str {
    if DOCKER_HUB_ALIASES.contains(&host) { DOCKER_HUB } else { host }
}

/// Lowercases, maps Docker Hub aliases and drops `:443`.
fn canonical(hostport: &str) -> String {
    let h = hostport.to_ascii_lowercase();
    let h = h.strip_suffix(":443").unwrap_or(&h);
    alias(h).to_string()
}

fn dns_name(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// The registry host a user typed, normalized: lowercase, without scheme, `/v1/` or `/v2/`, `:443`, and Docker Hub's
/// aliases as `docker.io`. IP addresses, `localhost` and paths are refused.
pub fn normalize(input: &str) -> Result<String, String> {
    let s = input.trim().to_ascii_lowercase();
    let s = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")).unwrap_or(&s);
    let (hostport, path) = s.split_once('/').unwrap_or((s, ""));
    if !matches!(path, "" | "v1" | "v1/" | "v2" | "v2/") {
        return Err(PATH_ERROR.into());
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            let n: u16 = p.parse().ok().filter(|&n| n > 0).ok_or_else(|| format!("{p}: not a port (1-65535)"))?;
            (h, (n != 443).then_some(n))
        }
        Some(_) => return Err(LOCAL_ERROR.into()),
        None => (hostport, None),
    };
    // Legacy IPv4 spellings (`127.1`, `0x7f.1`, `2130706433`) end in a numeric label; no DNS name does.
    let last = host.rsplit('.').next().unwrap_or_default();
    let numeric = !last.is_empty()
        && (last.bytes().all(|b| b.is_ascii_digit())
            || last.strip_prefix("0x").is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit())));
    let ip = numeric
        || host.parse::<std::net::Ipv4Addr>().is_ok()
        || host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::Ipv6Addr>().is_ok();
    if ip || host == "localhost" || host.ends_with(".localhost") {
        return Err(LOCAL_ERROR.into());
    }
    if host.is_empty() {
        return Err(PATH_ERROR.into());
    }
    if !dns_name(host) {
        return Err(format!("{host}: not a host name"));
    }
    let host = alias(host);
    Ok(match port {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    })
}

/// The explicit host of an image reference (`ghcr.io` in `ghcr.io/org/repo`), as written; None on Docker Hub.
fn explicit_host(image: &str) -> Option<&str> {
    let image = image.trim();
    let (first, _) = image.split_once('/')?;
    (first.contains(['.', ':']) || first == "localhost").then_some(first)
}

/// The normalized registry host of an image reference: its first path component when it has a dot or a port or is
/// `localhost` (the rule Docker uses), otherwise `docker.io`.
pub fn image_host(image: &str) -> String {
    explicit_host(image).map_or_else(|| DOCKER_HUB.to_string(), canonical)
}

/// The repository path of an image reference, for messages: without digest, tag and host, and under `library/` for
/// single-component Docker Hub names.
pub fn image_repo(image: &str) -> String {
    let image = image.trim();
    let image = image.split_once('@').map_or(image, |(n, _)| n);
    let name_start = image.rfind('/').map_or(0, |i| i + 1);
    let name = match image[name_start..].rfind(':') {
        Some(i) => &image[..name_start + i],
        None => image,
    };
    let repo = match explicit_host(name) {
        Some(h) => &name[h.len() + 1..],
        None => name,
    };
    if image_host(name) == DOCKER_HUB && !repo.contains('/') { format!("library/{repo}") } else { repo.to_string() }
}

/// The Docker config key of a normalized host: Docker Hub's legacy key, or the host (with its port).
pub fn config_key(host: &str) -> String {
    if host == DOCKER_HUB { DOCKER_HUB_KEY.to_string() } else { host.to_string() }
}

/// The host behind a [`RegistryAuth::server`] value.
pub fn server_host(server: &str) -> String {
    if server == DOCKER_HUB_KEY {
        return DOCKER_HUB.to_string();
    }
    normalize(server).unwrap_or_else(|_| server.trim().to_ascii_lowercase())
}

/// A Docker config (`config.json`) with one `auths` entry per credential, keyed by [`config_key`].
pub fn docker_config<'a>(auths: impl IntoIterator<Item = &'a RegistryAuth>) -> Vec<u8> {
    let mut map = serde_json::Map::new();
    for a in auths {
        let auth = B64.encode(format!("{}:{}", a.username, a.password));
        map.insert(config_key(&server_host(&a.server)), serde_json::json!({ "auth": auth }));
    }
    serde_json::to_vec(&serde_json::json!({ "auths": map })).expect("a JSON object serializes")
}

/// The credential for the host of `image`, if any.
pub fn matching<'a>(auths: &'a [RegistryAuth], image: &str) -> Option<&'a RegistryAuth> {
    let host = image_host(image);
    auths.iter().find(|a| server_host(&a.server) == host)
}

const REDACTED: &str = "[redacted]";

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"._~+/=-".contains(&b)
}

/// Replaces the value after `Bearer ` and `Basic ` (any case), keeping the scheme. A challenge parameter
/// (`Basic realm="…"`) is not a value and stays.
fn redact_schemes(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        let scheme = ["bearer", "basic"].into_iter().find(|s| {
            bytes.len() >= i + s.len()
                && bytes[i..i + s.len()].eq_ignore_ascii_case(s.as_bytes())
                && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
        });
        let Some(scheme) = scheme else {
            i += 1;
            continue;
        };
        let mut v = i + scheme.len();
        if v >= bytes.len() || bytes[v] != b' ' {
            i += scheme.len();
            continue;
        }
        while v < bytes.len() && bytes[v] == b' ' {
            v += 1;
        }
        let mut end = v;
        while end < bytes.len() && token_char(bytes[end]) {
            end += 1;
        }
        if end == v || bytes.get(end) == Some(&b'"') {
            i = end.max(i + scheme.len());
            continue;
        }
        out.push_str(&text[copied..v]);
        out.push_str(REDACTED);
        copied = end;
        i = end;
    }
    out.push_str(&text[copied..]);
    out
}

/// `text` without the credentials' secrets: each password, its percent-encoded form and the base64 of
/// `username:password` become `[redacted]`, and so does any `Bearer`/`Basic` authorization value.
pub fn redact(text: &str, auths: &[&RegistryAuth]) -> String {
    let mut needles: Vec<String> = Vec::new();
    for a in auths.iter().filter(|a| !a.password.is_empty()) {
        needles.push(B64.encode(format!("{}:{}", a.username, a.password)));
        needles.push(percent_encode(&a.password));
        needles.push(a.password.clone());
    }
    needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
    needles.dedup();
    let mut out = text.to_string();
    for n in &needles {
        if out.contains(n.as_str()) {
            out = out.replace(n.as_str(), REDACTED);
        }
    }
    redact_schemes(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(server: &str, user: &str, pass: &str) -> RegistryAuth {
        RegistryAuth { server: server.into(), username: user.into(), password: pass.into() }
    }

    #[test]
    fn docker_hub_aliases_are_one_registry() {
        for a in DOCKER_HUB_ALIASES {
            assert_eq!(normalize(a).unwrap(), "docker.io", "{a}");
            assert_eq!(image_host(&format!("{a}/acme/app:1")), "docker.io", "{a}");
        }
        assert_eq!(normalize("https://index.docker.io/v1/").unwrap(), "docker.io");
        assert_eq!(server_host(DOCKER_HUB_KEY), "docker.io");
    }

    #[test]
    fn normalize_accepts_hosts_and_refuses_the_rest() {
        assert_eq!(normalize(" GHCR.io/ ").unwrap(), "ghcr.io");
        assert_eq!(normalize("https://registry.example.com:443/v2/").unwrap(), "registry.example.com");
        assert_eq!(normalize("registry.example.com:5000").unwrap(), "registry.example.com:5000");
        assert_eq!(normalize("ghcr.io/acme").unwrap_err(), PATH_ERROR);
        for local in ["127.0.0.1", "192.0.2.1:5000", "localhost", "localhost:5000", "[::1]:5000", "::1"] {
            assert_eq!(normalize(local).unwrap_err(), LOCAL_ERROR, "{local}");
        }
        for legacy in ["127.1", "10.1", "0x7f.1", "2130706433", "0x7f000001", "127.0.1:5000", "a.0x1F"] {
            assert_eq!(normalize(legacy).unwrap_err(), LOCAL_ERROR, "{legacy}: a legacy IPv4 spelling");
        }
        assert_eq!(normalize("registry.0x.io").unwrap(), "registry.0x.io", "a numeric-looking inner label is fine");
        for bad in ["", "ghcr", "-a.io", "a_b.io", "ghcr.io:0", "ghcr.io:99999", "ghcr.io:x"] {
            assert!(normalize(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn image_host_and_repo() {
        assert_eq!(image_host("nginx"), "docker.io");
        assert_eq!(image_host("acme/app"), "docker.io");
        assert_eq!(image_host("docker.io/acme/app"), "docker.io");
        assert_eq!(image_host("ghcr.io/acme/app:1"), "ghcr.io");
        assert_eq!(image_host("localhost:5000/x"), "localhost:5000");
        assert_eq!(image_host("REGISTRY.example.com:443/x"), "registry.example.com");
        assert_eq!(image_repo("nginx"), "library/nginx");
        assert_eq!(image_repo("acme/app:2"), "acme/app");
        assert_eq!(image_repo(&format!("ghcr.io/org/repo@sha256:{}", "a".repeat(64))), "org/repo");
        assert_eq!(image_repo("localhost:5000/x:1"), "x");
        assert_eq!(image_repo("docker.io/redis:7"), "library/redis");
    }

    #[test]
    fn config_keys_and_docker_config() {
        assert_eq!(config_key("docker.io"), DOCKER_HUB_KEY);
        assert_eq!(config_key("registry.example.com:5000"), "registry.example.com:5000");
        let hub = auth("docker.io", "u", "p4ssword");
        let cfg: serde_json::Value = serde_json::from_slice(&docker_config(Some(&hub))).unwrap();
        assert_eq!(cfg["auths"][DOCKER_HUB_KEY]["auth"], B64.encode("u:p4ssword"));
        let empty: serde_json::Value = serde_json::from_slice(&docker_config(None)).unwrap();
        assert_eq!(empty, serde_json::json!({"auths": {}}));
    }

    #[test]
    fn matching_is_by_host() {
        let list = [auth(DOCKER_HUB_KEY, "a", "aaaaaaaa"), auth("ghcr.io", "b", "bbbbbbbb")];
        assert_eq!(matching(&list, "nginx:1").unwrap().username, "a");
        assert_eq!(matching(&list, "ghcr.io/acme/x").unwrap().username, "b");
        assert!(matching(&list, "registry.gitlab.com/acme/x").is_none());
    }

    #[test]
    fn redact_removes_secrets() {
        let a = auth("ghcr.io", "bob", "s3cr3t/t0ken+x");
        let b64 = B64.encode("bob:s3cr3t/t0ken+x");
        let text = format!("pass s3cr3t/t0ken+x enc s3cr3t%2Ft0ken%2Bx pair {b64} end");
        assert_eq!(redact(&text, &[&a]), "pass [redacted] enc [redacted] pair [redacted] end");
        assert_eq!(redact("Authorization: Bearer abc.def", &[]), "Authorization: Bearer [redacted]");
        assert_eq!(redact("authorization: basic Ym9iOng=, next", &[]), "authorization: basic [redacted], next");
        assert_eq!(redact("WWW-Authenticate: Basic realm=\"test\"", &[]), "WWW-Authenticate: Basic realm=\"test\"");
        let plain = "Step 1/3 : FROM alpine:3.20 — pulling layers";
        assert_eq!(redact(plain, &[&a]), plain);
    }
}
