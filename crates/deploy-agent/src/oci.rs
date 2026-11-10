//! Images built in a helper reach the Engine through the agent only. BuildKit exports each image as an OCI image
//! layout directory into the build helper (which has no access to the Engine); the agent downloads that directory
//! through the Engine API, checks it and loads it with `POST /images/load`, then tags it.
//!
//! Nothing the helper wrote is passed on as it is. While the archive streams in, every blob is hashed and kept only
//! under its verified `blobs/sha256/<digest>` name, in a load archive the agent writes itself into a staging
//! directory of its state (no symbolic link, no other path, no `index.json` or `manifest.json` of the helper). The
//! helper's `index.json` must lead to exactly one image (attestation manifests aside), whose configuration carries
//! the resource and deployment labels of the build; the agent then writes an `index.json` and a `manifest.json` that
//! name that image only, without any tag or reference name, so a load can never retag another image of the
//! server. After the load, the image the Engine reports must be that one (its configuration digest with the classic
//! image store, its manifest digest with the containerd image store), with the same labels, before it is tagged
//! `owd/<resource>:<deployment>` by the agent. The SPDX document of BuildKit's SBOM attestation for that image, if
//! any, comes back with it (see [`crate::sbom`]).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use bollard::Docker;
use bollard::query_parameters::{DownloadFromContainerOptionsBuilder, ImportImageOptionsBuilder};
use bytes::Bytes;
use deploy_proto::msg::{LABEL_DEPLOYMENT, LABEL_RESOURCE};
use futures_util::StreamExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::docker::{message, split_tag};

/// Index, manifest, configuration or attestation larger than this is refused: they are small JSON documents.
const MAX_METADATA_BYTES: u64 = 4 << 20;
/// Blobs kept in memory while the archive streams (the small ones, for the checks): at most this much in all.
const MAX_KEPT_BYTES: u64 = 64 << 20;
/// Predicate type of an SPDX SBOM in an in-toto statement of an attestation manifest.
const SPDX_PREDICATE: &str = "https://spdx.dev/Document";

const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
/// Layer types every Engine loads.
const LAYER_TYPES: [&str; 6] = [
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.docker.image.rootfs.diff.tar.zstd",
];

/// The labels a built image must carry.
#[derive(Clone, Copy)]
pub struct Expect<'a> {
    pub resource: &'a str,
    pub deployment: &'a str,
}

/// An image loaded and tagged.
#[derive(Debug)]
pub struct Loaded {
    /// Its ID as the Engine reports it (`sha256:…`).
    pub id: String,
    /// The SPDX JSON document of its SBOM attestation, if the build made one.
    pub sbom: Option<Vec<u8>>,
    /// Why the build's SBOM attestation was not read (it is too large to keep), if so: the image loads without it.
    pub sbom_skipped: Option<String>,
}

/// What the checks found in the layout: the image to load.
#[derive(Debug, PartialEq)]
struct Selected {
    /// Digest (hex) and size of the image manifest.
    manifest: (String, u64),
    manifest_type: String,
    /// Digest (hex) of the image configuration.
    config: String,
    /// Digests (hex) of the layers, in order.
    layers: Vec<String>,
    sbom: Option<Vec<u8>>,
    sbom_skipped: Option<String>,
}

/// The blobs of a layout as read: every digest with its size, and the content of the small ones.
#[derive(Default)]
struct Blobs {
    sizes: HashMap<String, u64>,
    kept: HashMap<String, Vec<u8>>,
}

impl Blobs {
    fn get(&self, digest: &str, what: &str) -> Result<&[u8], String> {
        let hex = hex_of(digest).ok_or_else(|| format!("{what}: invalid digest {digest:?}"))?;
        match (self.kept.get(hex), self.sizes.get(hex)) {
            (Some(b), _) => Ok(b),
            (None, Some(_)) => Err(format!("{what} {digest} is larger than {} MiB", MAX_METADATA_BYTES >> 20)),
            (None, None) => Err(format!("{what} {digest} is missing from the image layout")),
        }
    }
}

/// The hex of a `sha256:` digest, if it is one.
fn hex_of(digest: &str) -> Option<&str> {
    digest
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// A descriptor of the layout: media type, digest (hex) and size, checked against the blob it names.
fn descriptor<'a>(d: &'a Value, blobs: &Blobs, what: &str) -> Result<(&'a str, String, u64), String> {
    let digest = d.get("digest").and_then(Value::as_str).unwrap_or_default();
    let hex = hex_of(digest).ok_or_else(|| format!("{what}: invalid digest {digest:?}"))?;
    let size = d.get("size").and_then(Value::as_u64).ok_or_else(|| format!("{what} {digest}: no size"))?;
    match blobs.sizes.get(hex) {
        Some(s) if *s == size => {}
        Some(s) => return Err(format!("{what} {digest}: {s} bytes, the descriptor says {size}")),
        None => return Err(format!("{what} {digest} is missing from the image layout")),
    }
    Ok((d.get("mediaType").and_then(Value::as_str).unwrap_or_default(), hex.to_string(), size))
}

fn parse(bytes: &[u8], what: &str) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("{what}: {e}"))
}

/// Finds the one image of the layout and checks it: its blobs, layer types and labels, and its SPDX attestation.
fn select(index: &[u8], blobs: &Blobs, expect: Expect<'_>) -> Result<Selected, String> {
    let index = parse(index, "index.json")?;
    let mut images = Vec::new();
    let mut attestations = Vec::new();
    // Each level of the index (BuildKit nests the image index with its attestations under the layout's index).
    let mut level: Vec<Value> = index.get("manifests").and_then(Value::as_array).cloned().unwrap_or_default();
    for depth in 0..3 {
        let mut next = Vec::new();
        for d in &level {
            let (declared, hex, _) = descriptor(d, blobs, "manifest")?;
            let body = parse(blobs.get(&format!("sha256:{hex}"), "manifest")?, "manifest")?;
            let media = match declared {
                "" => body.get("mediaType").and_then(Value::as_str).unwrap_or_default().to_string(),
                m => m.to_string(),
            };
            match media.as_str() {
                OCI_INDEX | DOCKER_LIST if depth < 2 => {
                    next.extend(body.get("manifests").and_then(Value::as_array).cloned().unwrap_or_default());
                }
                OCI_MANIFEST | DOCKER_MANIFEST => {
                    let annotation = |k: &str| d.get("annotations").and_then(|a| a.get(k)).and_then(Value::as_str);
                    if annotation("vnd.docker.reference.type") == Some("attestation-manifest") {
                        let subject = annotation("vnd.docker.reference.digest").unwrap_or_default().to_string();
                        attestations.push((subject, body));
                    } else {
                        images.push((hex, d.get("size").and_then(Value::as_u64).unwrap_or(0), media, body));
                    }
                }
                m => return Err(format!("unexpected manifest type {m:?} in the image layout")),
            }
        }
        if next.is_empty() {
            break;
        }
        level = next;
    }
    let (hex, size, media, manifest) = match images.len() {
        1 => images.remove(0),
        n => return Err(format!("the build exported {n} images, not one")),
    };
    let (_, config, _) = descriptor(manifest.get("config").unwrap_or(&Value::Null), blobs, "image configuration")?;
    let mut layers = Vec::new();
    for l in manifest.get("layers").and_then(Value::as_array).into_iter().flatten() {
        let (t, digest, _) = descriptor(l, blobs, "layer")?;
        if !LAYER_TYPES.contains(&t) {
            return Err(format!("layer sha256:{digest} has the unsupported type {t:?}"));
        }
        layers.push(digest);
    }
    let conf = parse(blobs.get(&format!("sha256:{config}"), "image configuration")?, "image configuration")?;
    check_labels(conf.get("config").and_then(|c| c.get("Labels")), expect)?;
    let diff_ids = conf.get("rootfs").and_then(|r| r.get("diff_ids")).and_then(Value::as_array).map_or(0, Vec::len);
    if diff_ids != layers.len() {
        return Err(format!("the image has {} layers and {diff_ids} in its configuration", layers.len()));
    }
    let subject = format!("sha256:{hex}");
    let mut sbom = None;
    let mut sbom_skipped = None;
    for (_, att) in attestations.iter().filter(|(s, _)| *s == subject) {
        for l in att.get("layers").and_then(Value::as_array).into_iter().flatten() {
            let predicate =
                l.get("annotations").and_then(|a| a.get("in-toto.io/predicate-type")).and_then(Value::as_str);
            if sbom.is_some() || sbom_skipped.is_some() || predicate != Some(SPDX_PREDICATE) {
                continue;
            }
            let (_, digest, size) = descriptor(l, blobs, "attestation")?;
            // The SBOM is metadata about the image, not part of it: one too large to keep in memory never fails the
            // deployment (the image is checked and loaded without it, and the log says why there is no SBOM).
            if !blobs.kept.contains_key(&digest) {
                sbom_skipped = Some(format!(
                    "its SBOM attestation sha256:{digest} ({:.1} MiB) is larger than the {} MiB the agent reads",
                    size as f64 / (1 << 20) as f64,
                    MAX_METADATA_BYTES >> 20
                ));
                continue;
            }
            let statement = parse(blobs.get(&format!("sha256:{digest}"), "attestation")?, "attestation")?;
            if statement.get("predicateType").and_then(Value::as_str) == Some(SPDX_PREDICATE)
                && let Some(p) = statement.get("predicate")
            {
                sbom = Some(serde_json::to_vec(p).map_err(|e| e.to_string())?);
            }
        }
    }
    Ok(Selected { manifest: (hex, size), manifest_type: media, config, layers, sbom, sbom_skipped })
}

/// The resource and deployment labels of the build, exactly.
fn check_labels(labels: Option<&Value>, expect: Expect<'_>) -> Result<(), String> {
    let get = |k: &str| labels.and_then(|l| l.get(k)).and_then(Value::as_str);
    for (k, want) in [(LABEL_RESOURCE, expect.resource), (LABEL_DEPLOYMENT, expect.deployment)] {
        match get(k) {
            Some(v) if v == want => {}
            v => return Err(format!("the built image has the label {k}={v:?}, not {want:?}: refused")),
        }
    }
    Ok(())
}

/// The `index.json` and `manifest.json` the agent writes for the load: the selected image only, without a name.
fn load_metadata(s: &Selected) -> (Vec<u8>, Vec<u8>) {
    let index = json!({
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": [{"mediaType": s.manifest_type, "digest": format!("sha256:{}", s.manifest.0), "size": s.manifest.1}],
    });
    let manifest = json!([{
        "Config": format!("blobs/sha256/{}", s.config),
        "RepoTags": [],
        "Layers": s.layers.iter().map(|l| format!("blobs/sha256/{l}")).collect::<Vec<_>>(),
    }]);
    (serde_json::to_vec(&index).expect("json"), serde_json::to_vec(&manifest).expect("json"))
}

/// Whether the image the Engine reports after the load is the selected one.
fn is_selected(id: &str, s: &Selected) -> bool {
    hex_of(id).is_some_and(|h| h == s.config || h == s.manifest.0)
}

/// Appends a regular file to the load archive.
fn append<W: Write>(out: &mut tar::Builder<W>, path: &str, size: u64, data: impl Read) -> std::io::Result<()> {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_mode(0o644);
    h.set_size(size);
    h.set_mtime(0);
    out.append_data(&mut h, path, data)
}

/// Reads through `inner`, hashing what passes.
struct Hashing<R> {
    inner: R,
    hash: Sha256,
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hash.update(&buf[..n]);
        Ok(n)
    }
}

/// Turns the Engine's archive of layout directory `base` (read from `input`) into the load archive `out`: checks
/// every entry and blob digest, then the image ([`select`]), and appends the agent's own metadata.
fn convert<R: Read, W: Write>(input: R, base: &str, out: W, expect: Expect<'_>) -> Result<(Selected, W), String> {
    let mut archive = tar::Archive::new(input);
    let mut out = tar::Builder::new(out);
    let mut blobs = Blobs::default();
    let mut index = None;
    let mut kept = 0u64;
    let io = |e: std::io::Error| format!("read the image layout: {e}");
    for entry in archive.entries().map_err(io)? {
        let mut entry = entry.map_err(io)?;
        let path = entry.path().map_err(io)?.to_string_lossy().into_owned();
        let rel = path.trim_end_matches('/');
        let rel = match rel.strip_prefix(base) {
            Some("") => continue,
            Some(r) if r.starts_with('/') => &r[1..],
            _ => return Err(format!("unexpected entry {path:?} in the image layout")),
        };
        let kind = entry.header().entry_type();
        // Directories (`blobs`, BuildKit's empty `ingest`) carry nothing: what is in them is checked entry by entry.
        if kind.is_dir() {
            continue;
        }
        if kind != tar::EntryType::Regular && kind != tar::EntryType::Continuous {
            return Err(format!("unexpected entry {rel:?} ({kind:?}) in the image layout"));
        }
        let size = entry.size();
        match rel {
            "oci-layout" => continue,
            "index.json" => {
                if size > MAX_METADATA_BYTES {
                    return Err("index.json is too large".into());
                }
                let mut b = Vec::with_capacity(size as usize);
                entry.read_to_end(&mut b).map_err(io)?;
                index = Some(b);
            }
            _ => {
                let hex = rel
                    .strip_prefix("blobs/sha256/")
                    .filter(|h| hex_of(&format!("sha256:{h}")).is_some())
                    .ok_or_else(|| format!("unexpected entry {rel:?} in the image layout"))?
                    .to_string();
                if blobs.sizes.contains_key(&hex) {
                    return Err(format!("blob {hex} appears twice in the image layout"));
                }
                let name = format!("blobs/sha256/{hex}");
                let digest = if size <= MAX_METADATA_BYTES && kept + size <= MAX_KEPT_BYTES {
                    let mut b = Vec::with_capacity(size as usize);
                    entry.read_to_end(&mut b).map_err(io)?;
                    let digest = hex::encode(Sha256::digest(&b));
                    append(&mut out, &name, size, b.as_slice()).map_err(|e| format!("write the load archive: {e}"))?;
                    kept += size;
                    blobs.kept.insert(hex.clone(), b);
                    digest
                } else {
                    let mut r = Hashing { inner: &mut entry, hash: Sha256::new() };
                    append(&mut out, &name, size, &mut r).map_err(|e| format!("write the load archive: {e}"))?;
                    hex::encode(r.hash.finalize())
                };
                if digest != hex {
                    return Err(format!("blob {hex} of the image layout has the digest {digest}: refused"));
                }
                blobs.sizes.insert(hex, size);
            }
        }
    }
    let index = index.ok_or("the image layout has no index.json")?;
    let selected = select(&index, &blobs, expect)?;
    let (index, manifest) = load_metadata(&selected);
    let w = |e: std::io::Error| format!("write the load archive: {e}");
    append(&mut out, "oci-layout", 30, &br#"{"imageLayoutVersion":"1.0.0"}"#[..]).map_err(w)?;
    append(&mut out, "index.json", index.len() as u64, index.as_slice()).map_err(w)?;
    append(&mut out, "manifest.json", manifest.len() as u64, manifest.as_slice()).map_err(w)?;
    let out = out.into_inner().map_err(w)?;
    Ok((selected, out))
}

/// A blocking reader over chunks an async task forwards (the Engine's archive stream).
struct ChannelReader {
    rx: mpsc::Receiver<Result<Bytes, String>>,
    chunk: Bytes,
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.chunk.is_empty() {
            match self.rx.blocking_recv() {
                Some(Ok(c)) => self.chunk = c,
                Some(Err(e)) => return Err(std::io::Error::other(e)),
                None => return Ok(0),
            }
        }
        let n = buf.len().min(self.chunk.len());
        buf[..n].copy_from_slice(&self.chunk.split_to(n));
        Ok(n)
    }
}

/// A directory of the agent's state for load archives, removed with what is in it when dropped. In the state
/// directory rather than /tmp, which may be memory.
struct Staging(PathBuf);

impl Staging {
    fn new() -> Result<Staging, String> {
        let root = staging_root();
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(&root).map_err(|e| format!("{}: {e}", root.display()))?;
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).expect("OS randomness");
        let p = root.join(hex::encode(r));
        b.recursive(false).create(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        Ok(Staging(p))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Where load archives are staged: `$OWDEPLOY_AGENT_STATE/staging`.
pub fn staging_root() -> PathBuf {
    crate::state_dir().join("staging")
}

/// Removes what an earlier agent process left in the staging directory (it stopped in the middle of a load).
pub fn remove_leftover_staging() {
    let _ = std::fs::remove_dir_all(staging_root());
}

/// Loads the OCI image layout directory `dir` of `container` into the Engine as `tag`, after the checks above.
pub async fn load(
    d: &Docker,
    container: &str,
    dir: &str,
    expect: Expect<'_>,
    tag: &str,
    cancel: &CancellationToken,
) -> Result<Loaded, String> {
    let base = dir.rsplit('/').next().unwrap_or(dir).to_string();
    let staging = Staging::new()?;
    let file = staging.path().join("image.tar");
    let (tx, rx) = mpsc::channel(16);
    let mut archive =
        d.download_from_container(container, Some(DownloadFromContainerOptionsBuilder::default().path(dir).build()));
    let forward = async {
        while let Some(chunk) = archive.next().await {
            let failed = chunk.is_err();
            if tx.send(chunk.map_err(|e| format!("download the image: {}", message(&e)))).await.is_err() || failed {
                break;
            }
        }
        drop(tx);
    };
    let (resource, deployment) = (expect.resource.to_string(), expect.deployment.to_string());
    let path = file.clone();
    let blocking = tokio::task::spawn_blocking(move || {
        let out = std::fs::File::create(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let expect = Expect { resource: &resource, deployment: &deployment };
        let (selected, out) =
            convert(ChannelReader { rx, chunk: Bytes::new() }, &base, std::io::BufWriter::new(out), expect)?;
        out.into_inner().map_err(|e| e.to_string())?.sync_all().map_err(|e| e.to_string())?;
        Ok::<_, String>(selected)
    });
    let converted = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(crate::CANCELLED.into()),
        (_, r) = futures_util::future::join(forward, blocking) => r,
    };
    let selected = converted.map_err(|e| format!("check the image: {e}"))??;

    let body = tokio::fs::File::open(&file).await.map_err(|e| format!("{}: {e}", file.display()))?;
    let body = bollard::body_try_stream(tokio_util::io::ReaderStream::new(body));
    let mut s = d.import_image(ImportImageOptionsBuilder::default().quiet(true).build(), body, None);
    let mut reported = Vec::new();
    loop {
        let item = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(crate::CANCELLED.into()),
            i = s.next() => i,
        };
        let Some(item) = item else { break };
        let info = item.map_err(|e| format!("load the image: {}", message(&e)))?;
        for line in info.stream.iter().flat_map(|s| s.lines()) {
            if let Some(id) = line.strip_prefix("Loaded image ID: ").or_else(|| line.strip_prefix("Loaded image: ")) {
                reported.push(id.trim().to_string());
            }
        }
    }
    drop(staging);
    if let Some(other) = reported.iter().find(|id| !is_selected(id, &selected)) {
        return Err(format!("the Engine loaded {other}, not the image checked: refused"));
    }
    // The Engine names the image by its configuration (classic store) or manifest (containerd store) digest.
    let mut image = None;
    for id in [&selected.config, &selected.manifest.0] {
        match d.inspect_image(&format!("sha256:{id}")).await {
            Ok(i) => {
                image = Some(i);
                break;
            }
            Err(e) if crate::docker::is_not_found(&e) => {}
            Err(e) => return Err(format!("inspect the loaded image: {}", message(&e))),
        }
    }
    let image = image.ok_or("the loaded image is not in the Engine")?;
    let id = image.id.unwrap_or_default();
    if !is_selected(&id, &selected) {
        return Err(format!("the Engine reports the image {id}, not the image checked: refused"));
    }
    let labels = image.config.and_then(|c| c.labels).map(|l| json!(l));
    check_labels(labels.as_ref(), expect)?;
    let (repo, t) = split_tag(tag);
    let opts =
        bollard::query_parameters::TagImageOptionsBuilder::default().repo(repo).tag(t.unwrap_or("latest")).build();
    d.tag_image(&id, Some(opts)).await.map_err(|e| format!("tag {id} as {tag}: {}", message(&e)))?;
    Ok(Loaded { id, sbom: selected.sbom, sbom_skipped: selected.sbom_skipped })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECT: Expect<'static> = Expect { resource: "app_01J", deployment: "dep_01X" };

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    /// An OCI layout as BuildKit exports it (index → image index → image manifest and its SBOM attestation), as the
    /// Engine archives the directory `img`, with the blobs as given (`tamper` changes the archive before it is read).
    struct Layout {
        blobs: Vec<(String, Vec<u8>)>,
        index: Value,
        manifest: String,
    }

    fn layout(labels: Value, layers: usize) -> Layout {
        layout_with_sbom(labels, layers, 0)
    }

    /// [`layout`] whose SPDX document carries `padding` more bytes (a large image's SBOM).
    fn layout_with_sbom(labels: Value, layers: usize, padding: usize) -> Layout {
        let mut blobs = Vec::new();
        let mut add = |b: Vec<u8>| {
            let h = sha(&b);
            blobs.push((h.clone(), b.clone()));
            (h, b.len())
        };
        let layer_list: Vec<(String, usize)> = (0..layers).map(|i| add(format!("layer{i}").into_bytes())).collect();
        let config = serde_json::to_vec(&json!({
            "architecture": "arm64", "os": "linux", "config": {"Labels": labels},
            "rootfs": {"type": "layers", "diff_ids": layer_list.iter().map(|(h, _)| format!("sha256:{h}")).collect::<Vec<_>>()},
        }))
        .unwrap();
        let (ch, cl) = add(config);
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2, "mediaType": OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": format!("sha256:{ch}"), "size": cl},
            "layers": layer_list.iter().map(|(h, l)| json!({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": format!("sha256:{h}"), "size": l})).collect::<Vec<_>>(),
        }))
        .unwrap();
        let (mh, ml) = add(manifest);
        let statement = serde_json::to_vec(&json!({
            "_type": "https://in-toto.io/Statement/v1", "predicateType": SPDX_PREDICATE, "subject": [],
            "predicate": {"spdxVersion": "SPDX-2.3", "name": "sbom", "comment": "x".repeat(padding)},
        }))
        .unwrap();
        let (sh, sl) = add(statement);
        let att = serde_json::to_vec(&json!({
            "schemaVersion": 2, "mediaType": OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": format!("sha256:{}", sha(b"{}")), "size": 2},
            "layers": [{"mediaType": "application/vnd.in-toto+json", "digest": format!("sha256:{sh}"), "size": sl,
                        "annotations": {"in-toto.io/predicate-type": SPDX_PREDICATE}}],
        }))
        .unwrap();
        let (ah, al) = add(att);
        let inner = serde_json::to_vec(&json!({
            "schemaVersion": 2, "mediaType": OCI_INDEX,
            "manifests": [
                {"mediaType": OCI_MANIFEST, "digest": format!("sha256:{mh}"), "size": ml, "platform": {"architecture": "arm64", "os": "linux"}},
                {"mediaType": OCI_MANIFEST, "digest": format!("sha256:{ah}"), "size": al,
                 "annotations": {"vnd.docker.reference.digest": format!("sha256:{mh}"), "vnd.docker.reference.type": "attestation-manifest"}},
            ],
        }))
        .unwrap();
        let (ih, il) = add(inner);
        let index = json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [
            {"mediaType": OCI_INDEX, "digest": format!("sha256:{ih}"), "size": il,
             "annotations": {"org.opencontainers.image.ref.name": "owd/router:latest", "io.containerd.image.name": "docker.io/library/caddy:2"}}]});
        Layout { blobs, index, manifest: mh }
    }

    impl Layout {
        /// The layout as the Engine archives the directory `img` of the helper, then `extra` entries.
        fn archive(&self, extra: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
            let mut b = tar::Builder::new(Vec::new());
            for p in ["img/", "img/blobs/", "img/blobs/sha256/", "img/ingest/"] {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(tar::EntryType::Directory);
                h.set_size(0);
                h.set_mode(0o755);
                b.append_data(&mut h, p, std::io::empty()).unwrap();
            }
            for (h, data) in &self.blobs {
                append(&mut b, &format!("img/blobs/sha256/{h}"), data.len() as u64, data.as_slice()).unwrap();
            }
            let index = serde_json::to_vec(&self.index).unwrap();
            append(&mut b, "img/index.json", index.len() as u64, index.as_slice()).unwrap();
            append(&mut b, "img/oci-layout", 2, &b"{}"[..]).unwrap();
            extra(&mut b);
            b.into_inner().unwrap()
        }
    }

    fn run(archive: &[u8], expect: Expect<'_>) -> Result<(Selected, Vec<u8>), String> {
        convert(archive, "img", Vec::new(), expect)
    }

    fn entries(tar: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut a = tar::Archive::new(tar);
        a.entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let mut b = Vec::new();
                e.read_to_end(&mut b).unwrap();
                (e.path().unwrap().to_string_lossy().into_owned(), b)
            })
            .collect()
    }

    fn labels(resource: &str, deployment: &str) -> Value {
        json!({LABEL_RESOURCE: resource, LABEL_DEPLOYMENT: deployment, "org.opencontainers.image.title": "x"})
    }

    #[test]
    fn a_checked_image_loads_by_digest_without_any_name_and_brings_its_sbom() {
        let l = layout(labels("app_01J", "dep_01X"), 2);
        let (s, out) = run(&l.archive(|_| {}), EXPECT).unwrap();
        assert_eq!(s.manifest.0, l.manifest);
        assert_eq!(s.layers.len(), 2);
        let sbom: Value = serde_json::from_slice(s.sbom.as_deref().unwrap()).unwrap();
        assert_eq!(sbom["spdxVersion"], "SPDX-2.3");
        let out = entries(&out);
        let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names
                .iter()
                .all(|n| n.starts_with("blobs/sha256/") || ["oci-layout", "index.json", "manifest.json"].contains(n)),
            "{names:?}"
        );
        let index: Value = serde_json::from_slice(&out.iter().find(|(n, _)| n == "index.json").unwrap().1).unwrap();
        assert_eq!(index["manifests"].as_array().unwrap().len(), 1);
        assert_eq!(index["manifests"][0]["digest"], format!("sha256:{}", l.manifest));
        assert!(index["manifests"][0].get("annotations").is_none(), "no reference name reaches the Engine");
        let manifest: Value =
            serde_json::from_slice(&out.iter().find(|(n, _)| n == "manifest.json").unwrap().1).unwrap();
        assert_eq!(manifest[0]["RepoTags"], json!([]));
        assert_eq!(manifest[0]["Config"], format!("blobs/sha256/{}", s.config));
        // What the Engine may report after the load.
        assert!(is_selected(&format!("sha256:{}", s.config), &s));
        assert!(is_selected(&format!("sha256:{}", l.manifest), &s));
        assert!(!is_selected(&format!("sha256:{}", sha(b"other")), &s));
        assert!(!is_selected(&s.config, &s), "only sha256: digests");
        // A manifest.json of the helper (it could tag any image) is refused, not passed on.
        let tagged = l.archive(|b| append(b, "img/manifest.json", 2, &b"[]"[..]).unwrap());
        assert!(run(&tagged, EXPECT).unwrap_err().contains("manifest.json"));
    }

    #[test]
    fn an_sbom_attestation_too_large_to_read_is_skipped_and_the_image_still_loads() {
        let big = MAX_METADATA_BYTES as usize + 1;
        let l = layout_with_sbom(labels("app_01J", "dep_01X"), 2, big);
        let (s, out) = run(&l.archive(|_| {}), EXPECT).unwrap();
        assert_eq!(s.manifest.0, l.manifest);
        assert_eq!(s.layers.len(), 2);
        assert_eq!(s.sbom, None);
        let why = s.sbom_skipped.as_deref().unwrap();
        assert!(why.contains("SBOM attestation") && why.contains("larger than the 4 MiB"), "{why}");
        let out = entries(&out);
        let index: Value = serde_json::from_slice(&out.iter().find(|(n, _)| n == "index.json").unwrap().1).unwrap();
        assert_eq!(index["manifests"][0]["digest"], format!("sha256:{}", l.manifest));
        // The 4 MiB cap still holds for what the load needs: an oversized image configuration is refused.
        let huge = labels("app_01J", "dep_01X");
        let mut huge = huge.as_object().unwrap().clone();
        huge.insert("padding".into(), json!("x".repeat(big)));
        let l = layout(Value::Object(huge), 1);
        assert!(run(&l.archive(|_| {}), EXPECT).unwrap_err().contains("larger than 4 MiB"));
    }

    #[test]
    fn images_of_another_resource_or_deployment_or_without_labels_are_refused() {
        for (labels, needle) in [
            (labels("app_02", "dep_01X"), LABEL_RESOURCE),
            (labels("app_01J", "dep_00W"), LABEL_DEPLOYMENT),
            (json!(null), LABEL_RESOURCE),
            (json!({LABEL_RESOURCE: "app_01J"}), LABEL_DEPLOYMENT),
        ] {
            let e = run(&layout(labels.clone(), 1).archive(|_| {}), EXPECT).unwrap_err();
            assert!(e.contains(needle) && e.contains("refused"), "{labels}: {e}");
        }
    }

    #[test]
    fn tampered_or_unexpected_layouts_are_refused() {
        let l = layout(labels("app_01J", "dep_01X"), 1);
        // A blob whose content does not match its name.
        let mut bad = layout(labels("app_01J", "dep_01X"), 1);
        let (h, _) = bad.blobs[0].clone();
        bad.blobs[0] = (h, b"layerX".to_vec());
        assert!(run(&bad.archive(|_| {}), EXPECT).unwrap_err().contains("digest"));
        // A symbolic link (to a file of the server, say) or any other path.
        let link = l.archive(|b| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            b.append_link(&mut h, "img/blobs/sha256/".to_string() + &"a".repeat(64), "/etc/shadow").unwrap();
        });
        assert!(run(&link, EXPECT).unwrap_err().contains("Symlink"));
        for path in ["img/blobs/sha256/notadigest", "elsewhere/x", "img/blobs/sha512/ab"] {
            let other = l.archive(|b| append(b, path, 1, &b"x"[..]).unwrap());
            assert!(run(&other, EXPECT).unwrap_err().contains("unexpected entry"), "{path}");
        }
        // Two images in one layout.
        let mut two = layout(labels("app_01J", "dep_01X"), 1);
        let first = two.index["manifests"][0].clone();
        let second = layout(labels("app_01J", "dep_01X"), 2);
        let extra: Vec<_> =
            second.blobs.iter().filter(|(h, _)| !two.blobs.iter().any(|(x, _)| x == h)).cloned().collect();
        two.blobs.extend(extra);
        two.index["manifests"] = json!([first, second.index["manifests"][0]]);
        assert!(run(&two.archive(|_| {}), EXPECT).unwrap_err().contains("2 images"));
        // A descriptor whose size is not the blob's.
        let mut sized = layout(labels("app_01J", "dep_01X"), 1);
        sized.index["manifests"][0]["size"] = json!(1);
        assert!(run(&sized.archive(|_| {}), EXPECT).unwrap_err().contains("bytes"));
        // No index.
        let mut b = tar::Builder::new(Vec::new());
        append(&mut b, "img/oci-layout", 2, &b"{}"[..]).unwrap();
        assert!(run(&b.into_inner().unwrap(), EXPECT).unwrap_err().contains("no index.json"));
    }
}
