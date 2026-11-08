//! Software bills of materials of the images a deployment runs: an SPDX 2.3 JSON document per image, sent to the
//! control plane as `Event::Sbom` parts of the deployment command, after the image exists and before the command's
//! result (gzip, then base64, cut into parts of at most [`MAX_SBOM_PART_BYTES`] characters; at most
//! [`MAX_SBOM_PARTS`] parts, else nothing is sent and the log says the SBOM was too large).
//!
//! - Built images: the SPDX document of BuildKit's SBOM attestation, from the image layout the agent loaded
//!   ([`crate::oci`]).
//! - Pulled images: the registry's SPDX attestation for the Engine's platform, when the image has one
//!   (`docker buildx imagetools inspect` of the pulled digest, in a source helper); otherwise syft (pinned and
//!   checksummed in the helper image) scans the image the agent exports from the Engine, in a helper without network.
//!   An image reused from the server (a redeployment, a rollback) goes the same way as a pulled one without
//!   attestation.
//!
//! Documents are cached by image ID in `$OWDEPLOY_AGENT_STATE/sbom` (gzip, the [`CACHE_ENTRIES`] most recent), so a
//! redeployment of the same image is not scanned again. Nothing here ever fails a deployment: what goes wrong is a
//! system line of its log.

use std::io::Write;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use bollard::Docker;
use deploy_proto::msg::{Event, MAX_SBOM_PART_BYTES, MAX_SBOM_PARTS, RegistryAuth};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::builder::Helper;
use crate::docker::message;
use crate::events::Events;

/// Largest SPDX document sent, uncompressed (what the control plane accepts).
const MAX_DOCUMENT_BYTES: usize = 64 << 20;
/// Documents kept in the cache.
const CACHE_ENTRIES: usize = 256;

/// The registry's SBOM attestation of an image, read by buildx (no Engine involved). Registry credentials, if any,
/// arrive on stdin into the helper's memory-only tmpfs.
const REGISTRY_SCRIPT: &str = r#"set -eu
export DOCKER_CONFIG=/run/owd/docker
mkdir -p "$DOCKER_CONFIG"
cat > "$DOCKER_CONFIG/config.json"
exec docker buildx imagetools inspect --format '{{json .SBOM}}' "$OWD_REF"
"#;

/// syft on the image archive the agent unpacked into /scan/img (`docker save` format), without network.
const SCAN_SCRIPT: &str = r#"set -eu
cd /scan/img
tar -cf /scan/image.tar .
cd /
rm -rf /scan/img
exec syft scan "docker-archive:/scan/image.tar" -o spdx-json -q --source-name "$OWD_NAME"
"#;

/// Checks `doc` is an SPDX JSON document of a size the control plane takes; returns its package count.
fn check(doc: &[u8]) -> Result<usize, String> {
    if doc.len() > MAX_DOCUMENT_BYTES {
        return Err(format!("{} MiB, more than {} MiB", doc.len() >> 20, MAX_DOCUMENT_BYTES >> 20));
    }
    let v: Value = serde_json::from_slice(doc).map_err(|e| format!("not JSON: {e}"))?;
    match v.get("spdxVersion").and_then(Value::as_str) {
        Some(s) if s.starts_with("SPDX-2.") => Ok(v.get("packages").and_then(Value::as_array).map_or(0, Vec::len)),
        _ => Err("not an SPDX 2 document".into()),
    }
}

fn gzip(doc: &[u8]) -> Result<Vec<u8>, String> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(doc).and_then(|_| e.finish()).map_err(|e| e.to_string())
}

/// The `data` of each part of a compressed document; None when it takes more than [`MAX_SBOM_PARTS`] parts.
fn parts(gz: &[u8]) -> Option<Vec<String>> {
    let text = B64.encode(gz);
    let parts: Vec<String> =
        text.as_bytes().chunks(MAX_SBOM_PART_BYTES).map(|c| String::from_utf8(c.to_vec()).expect("base64")).collect();
    (parts.len() <= MAX_SBOM_PARTS as usize).then_some(parts)
}

/// The cache file of `image_id` (`sha256:<hex>`).
fn cache_path(image_id: &str) -> Option<PathBuf> {
    let hex = image_id.strip_prefix("sha256:")?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| crate::state_dir().join("sbom").join(format!("{hex}.spdx.json.gz")))
}

fn cached(image_id: &str) -> Option<Vec<u8>> {
    std::fs::read(cache_path(image_id)?).ok()
}

/// Keeps `gz` for `image_id`, then drops the oldest documents beyond [`CACHE_ENTRIES`]. Best effort.
fn remember(image_id: &str, gz: &[u8]) {
    let Some(path) = cache_path(image_id) else { return };
    let Some(dir) = path.parent() else { return };
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    if b.create(dir).is_err() {
        return;
    }
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, gz).and_then(|_| std::fs::rename(&tmp, &path)).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut files: Vec<_> =
        rd.flatten().filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path()))).collect();
    if files.len() > CACHE_ENTRIES {
        files.sort();
        for (_, p) in &files[..files.len() - CACHE_ENTRIES] {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Sends the compressed document `gz` of `image_id` as `Event::Sbom` parts.
async fn send_compressed(ev: &Events, image_id: &str, service: Option<&str>, gz: &[u8], what: &str) {
    let Some(parts) = parts(gz) else {
        ev.system(format!(
            "The SBOM of {} is too large to send ({} MiB compressed): not sent",
            short(image_id),
            gz.len() >> 20
        ))
        .await;
        return;
    };
    let last = parts.len() - 1;
    for (i, data) in parts.into_iter().enumerate() {
        let event = Event::Sbom {
            image_digest: image_id.to_string(),
            service: service.map(str::to_string),
            part: i as u32,
            last: i == last,
            data,
        };
        ev.event(event).await;
    }
    ev.system(format!("Sent the SBOM of {} ({what})", short(image_id))).await;
}

/// Sends `doc`, the SPDX document of `image_id`, and caches it.
async fn send(ev: &Events, image_id: &str, service: Option<&str>, doc: &[u8], source: &str) {
    let r = check(doc).and_then(|n| Ok((n, gzip(doc)?)));
    match r {
        Ok((packages, gz)) => {
            remember(image_id, &gz);
            send_compressed(ev, image_id, service, &gz, &format!("{source}, {packages} packages")).await;
        }
        Err(e) => ev.system(format!("No SBOM for {}: {e}", short(image_id))).await,
    }
}

fn short(id: &str) -> &str {
    let id = id.strip_prefix("sha256:").unwrap_or(id);
    &id[..id.len().min(12)]
}

/// Sends the SBOM of an image the deployment built and loaded ([`crate::oci::Loaded`]).
pub async fn built(ev: &Events, image: &crate::oci::Loaded, service: Option<&str>) {
    match &image.sbom {
        Some(doc) => send(ev, &image.id, service, doc, "BuildKit attestation").await,
        None => ev.system(format!("No SBOM for {}: the build made no SBOM attestation", short(&image.id))).await,
    }
}

/// Where a pulled image comes from, for its registry attestation.
pub struct Pulled<'a> {
    /// The reference pulled.
    pub reference: &'a str,
    pub auth: Option<&'a RegistryAuth>,
}

/// Sends the SBOM of image `image_id` (as the Engine has it, named `name` in the log and the document): from the
/// cache, the registry's attestation when `pulled`, else syft. Best effort: failures are logged.
#[allow(clippy::too_many_arguments)]
pub async fn of_image(
    d: &Docker,
    resource: &str,
    image_id: &str,
    name: &str,
    pulled: Option<Pulled<'_>>,
    service: Option<&str>,
    ev: &Events,
    cancel: &CancellationToken,
) {
    if let Some(gz) = cached(image_id) {
        send_compressed(ev, image_id, service, &gz, "already generated").await;
        return;
    }
    let image = match d.inspect_image(image_id).await {
        Ok(i) => i,
        Err(e) => return ev.system(format!("No SBOM for {name}: {}", message(&e))).await,
    };
    if let Some(p) = pulled {
        let digest = image.repo_digests.iter().flatten().find_map(|r| r.split_once('@').map(|(_, d)| d.to_string()));
        let platforms = platforms(image.os.as_deref(), image.architecture.as_deref(), image.variant.as_deref());
        if let Some(digest) = digest {
            let repo = crate::docker::split_tag(p.reference.split('@').next().unwrap_or(p.reference)).0;
            let reference = format!("{repo}@{digest}");
            match registry(d, resource, &reference, p.auth, &platforms, ev, cancel).await {
                Ok(Some(doc)) => return send(ev, image_id, service, &doc, "registry attestation").await,
                Ok(None) => {}
                Err(_) if cancel.is_cancelled() => return,
                Err(e) => ev.system(format!("Could not read the registry's SBOM attestation of {name}: {e}")).await,
            }
        }
    }
    match scan(d, resource, image_id, name, ev, cancel).await {
        Ok(doc) => send(ev, image_id, service, &doc, &format!("syft {}", crate::builder::SYFT_VERSION)).await,
        Err(_) if cancel.is_cancelled() => {}
        Err(e) => ev.system(format!("No SBOM for {name}: {e}")).await,
    }
}

/// The platform keys buildx may use for an image of `os`/`arch`/`variant`, most precise first.
fn platforms(os: Option<&str>, arch: Option<&str>, variant: Option<&str>) -> Vec<String> {
    let base = format!("{}/{}", os.unwrap_or("linux"), arch.unwrap_or_default());
    match variant.filter(|v| !v.is_empty()) {
        Some(v) => vec![format!("{base}/{v}"), base],
        None => vec![base],
    }
}

/// The SPDX document in buildx's `{{json .SBOM}}` of an image: the image's own (one platform) or the one of the
/// first of `platforms` it has.
fn registry_document(out: &[u8], platforms: &[String]) -> Option<Value> {
    let v: Value = serde_json::from_slice(out).ok()?;
    if let Some(doc) = v.get("SPDX") {
        return Some(doc.clone());
    }
    platforms.iter().find_map(|p| v.get(p)?.get("SPDX").cloned())
}

async fn registry(
    d: &Docker,
    resource: &str,
    reference: &str,
    auth: Option<&RegistryAuth>,
    platforms: &[String],
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<Option<Vec<u8>>, String> {
    let h = Helper::source(d, resource, ev).await?;
    let cmd = vec!["/bin/sh".to_string(), "-c".to_string(), REGISTRY_SCRIPT.to_string()];
    let r = h
        .output(
            cmd,
            vec![format!("OWD_REF={reference}")],
            Some(deploy_proto::registry::docker_config(auth)),
            MAX_DOCUMENT_BYTES * 2,
            ev,
            cancel,
        )
        .await;
    h.remove().await;
    let (code, out) = r?;
    if code != 0 {
        return Err(format!("exit code {code}"));
    }
    Ok(registry_document(&out, platforms).map(|doc| serde_json::to_vec(&doc).expect("json")))
}

async fn scan(
    d: &Docker,
    resource: &str,
    image_id: &str,
    name: &str,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, String> {
    ev.system(format!("Generating the SBOM of {name} with syft")).await;
    let h = Helper::scan(d, resource, ev).await?;
    let r = async {
        let archive = d.export_image(image_id);
        h.unpack("scan/img", archive, cancel).await.map_err(|e| format!("export the image: {e}"))?;
        let cmd = vec!["/bin/sh".to_string(), "-c".to_string(), SCAN_SCRIPT.to_string()];
        let env = vec![format!("OWD_NAME={name}"), "SYFT_CHECK_FOR_APP_UPDATE=false".to_string()];
        let (code, out) = h.output(cmd, env, None, MAX_DOCUMENT_BYTES, ev, cancel).await?;
        if code != 0 {
            return Err(format!("syft failed (exit code {code})"));
        }
        Ok(out)
    }
    .await;
    h.remove().await;
    r
}

/// The SPDX document of `parts` (as sent): for tests and the control plane's checks alike.
#[cfg(test)]
fn decode(parts: &[String]) -> Vec<u8> {
    use std::io::Read;
    let gz = B64.decode(parts.concat()).unwrap();
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz.as_slice()).read_to_end(&mut out).unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn documents_are_sent_in_bounded_parts_or_not_at_all() {
        let doc = serde_json::to_vec(&json!({"spdxVersion": "SPDX-2.3", "packages": [{"name": "a"}, {"name": "b"}]}))
            .unwrap();
        assert_eq!(check(&doc), Ok(2));
        let parts = parts(&gzip(&doc).unwrap()).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(decode(&parts), doc);
        // Incompressible data (random bytes) needs several parts, each within the limit, in order.
        let mut noise = vec![0u8; MAX_SBOM_PART_BYTES * 2];
        getrandom::fill(&mut noise).unwrap();
        let p = super::parts(&noise).unwrap();
        assert_eq!(p.len(), 3);
        assert!(p.iter().all(|x| x.len() <= MAX_SBOM_PART_BYTES));
        assert_eq!(B64.decode(p.concat()).unwrap(), noise);
        // Beyond the most parts: nothing.
        let too_many = vec![0u8; MAX_SBOM_PART_BYTES / 4 * 3 * MAX_SBOM_PARTS as usize + 1];
        assert!(super::parts(&too_many).is_none());
        assert!(check(b"{\"spdxVersion\":\"CycloneDX\"}").is_err());
        assert!(check(b"not json").is_err());
    }

    #[test]
    fn the_registry_attestation_of_the_engines_platform_is_chosen() {
        let doc = |n: &str| json!({"spdxVersion": "SPDX-2.3", "name": n});
        let multi = serde_json::to_vec(&json!({
            "linux/amd64": {"SPDX": doc("amd64")},
            "linux/arm64/v8": {"SPDX": doc("arm64")},
        }))
        .unwrap();
        let arm = platforms(Some("linux"), Some("arm64"), Some("v8"));
        assert_eq!(arm, ["linux/arm64/v8", "linux/arm64"]);
        assert_eq!(registry_document(&multi, &arm).unwrap()["name"], "arm64");
        assert_eq!(registry_document(&multi, &platforms(Some("linux"), Some("amd64"), None)).unwrap()["name"], "amd64");
        assert!(registry_document(&multi, &platforms(Some("linux"), Some("s390x"), None)).is_none());
        let single = serde_json::to_vec(&json!({"SPDX": doc("one")})).unwrap();
        assert_eq!(registry_document(&single, &arm).unwrap()["name"], "one");
        assert!(registry_document(b"null", &arm).is_none());
        assert!(registry_document(b"{}", &arm).is_none());
    }

    #[test]
    fn registry_credentials_go_to_the_config_of_their_server_only() {
        let docker_config = deploy_proto::registry::docker_config;
        let a = RegistryAuth { server: "ghcr.io".into(), username: "u".into(), password: "p".into() };
        let c: Value = serde_json::from_slice(&docker_config(Some(&a))).unwrap();
        assert_eq!(c, json!({"auths": {"ghcr.io": {"auth": B64.encode("u:p")}}}));
        let hub = RegistryAuth { server: deploy_proto::registry::DOCKER_HUB_KEY.into(), ..a.clone() };
        let c: Value = serde_json::from_slice(&docker_config(Some(&hub))).unwrap();
        assert!(c["auths"]["https://index.docker.io/v1/"].is_object(), "{c}");
        assert_eq!(serde_json::from_slice::<Value>(&docker_config(None)).unwrap(), json!({"auths": {}}));
    }
}
