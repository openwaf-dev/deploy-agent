//! Volumes and file mounts of an application. Named volumes `owd-<resource>-<name>` carry the resource label and
//! outlive deployments: they go only with `VolumeRemove`. File mounts are written by the agent under its state
//! directory, one directory per deployment (a running container keeps the content it started with while the next
//! deployment writes its own), and bind-mounted read-only. Anything else a container writes, anonymous volumes
//! included (an image's `VOLUME` without a mount at that path), goes with the container when the next deployment
//! replaces it: the deployment's log says so ([`anonymous_paths`]).

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use bollard::Docker;
use bollard::models::{Mount, MountType, VolumeCreateRequest};
use bollard::query_parameters::ListVolumesOptionsBuilder;
use deploy_proto::msg::{FileMount, LABEL_RESOURCE, VolumeMount};
use serde_json::{Value, json};

use crate::docker::{COMPOSE_PROJECT, app_containers, check_volume, client, is_not_found, message, valid_id};

/// Label with a volume's name within its application.
pub const LABEL_VOLUME: &str = "dev.openwaf.deploy.volume";
/// Largest file mount (a frame is at most 1 MiB anyway).
const MAX_FILE_BYTES: usize = 512 * 1024;

pub fn volume_name(resource: &str, name: &str) -> String {
    format!("owd-{}-{name}", resource.to_ascii_lowercase())
}

fn name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 48
        && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// An absolute container path, without `..`, `:` (Docker's volume syntax) or control characters.
fn path_ok(p: &str) -> bool {
    p.starts_with('/')
        && p.len() > 1
        && p.len() <= 1024
        && !p.contains(':')
        && !p.chars().any(char::is_control)
        && !p.split('/').any(|c| c == ".." || c == ".")
}

/// Checks volumes and files. `compose`: each must name its service.
pub fn validate(volumes: &[VolumeMount], files: &[FileMount], compose: bool) -> Result<(), String> {
    let mut targets = BTreeSet::new();
    let mut names = BTreeSet::new();
    for v in volumes {
        if !name_ok(&v.name) {
            return Err(format!("invalid volume name {:?}", v.name));
        }
        if !names.insert((v.service.clone(), v.name.as_str())) {
            return Err(format!("volume {} is mounted twice", v.name));
        }
        check_target(&mut targets, &v.path, v.service.as_deref(), compose)?;
    }
    for f in files {
        if f.content.len() > MAX_FILE_BYTES {
            return Err(format!("file {} is larger than {} KiB", f.path, MAX_FILE_BYTES / 1024));
        }
        check_target(&mut targets, &f.path, f.service.as_deref(), compose)?;
    }
    Ok(())
}

fn check_target<'a>(
    seen: &mut BTreeSet<(Option<&'a str>, &'a str)>,
    path: &'a str,
    service: Option<&'a str>,
    compose: bool,
) -> Result<(), String> {
    if !path_ok(path) {
        return Err(format!("invalid mount path {path:?}"));
    }
    match (compose, service) {
        (true, None) => return Err(format!("{path}: a Compose application's mount names its service")),
        (true, Some(s)) if !valid_id(s) => return Err(format!("invalid service {s:?}")),
        _ => {}
    }
    if !seen.insert((service.filter(|_| compose), path)) {
        return Err(format!("{path} is mounted twice"));
    }
    Ok(())
}

/// Creates the application's volumes that do not exist yet; an existing one must be the application's.
pub async fn ensure(d: &Docker, resource: &str, volumes: &[VolumeMount]) -> Result<(), String> {
    for v in volumes {
        let name = volume_name(resource, &v.name);
        match d.inspect_volume(&name).await {
            Ok(existing) => {
                check_volume(resource, &name, Some(&existing.labels))?;
                continue;
            }
            Err(e) if is_not_found(&e) => {}
            Err(e) => return Err(format!("inspect volume {name}: {}", message(&e))),
        }
        let labels = HashMap::from([
            (LABEL_RESOURCE.to_string(), resource.to_string()),
            (LABEL_VOLUME.to_string(), v.name.clone()),
        ]);
        let req = VolumeCreateRequest { name: Some(name.clone()), labels: Some(labels), ..Default::default() };
        d.create_volume(req).await.map_err(|e| format!("create volume {name}: {}", message(&e)))?;
    }
    Ok(())
}

/// Directory of an application's file mounts.
fn files_root(resource: &str) -> Result<PathBuf, String> {
    let state = crate::state_dir();
    // Bind mounts need an absolute host path.
    let state = std::path::absolute(&state).map_err(|e| format!("{}: {e}", state.display()))?;
    Ok(state.join("files").join(resource.to_ascii_lowercase()))
}

fn private_dir(p: &std::path::Path) -> Result<(), String> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(p).map_err(|e| format!("{}: {e}", p.display()))
}

/// Writes a deployment's files; returns (host path, file) pairs in order.
pub fn write_files<'a>(
    resource: &str,
    deployment: &str,
    files: &'a [FileMount],
) -> Result<Vec<(PathBuf, &'a FileMount)>, String> {
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let root = files_root(resource)?;
    let dir = root.join(deployment.to_ascii_lowercase());
    // 0700 directories keep the content from other users of the server. The files themselves are 0644: a bind
    // mount exposes the file's own mode in the container, whose process may run as any user.
    private_dir(&root)?;
    let _ = std::fs::remove_dir_all(&dir);
    private_dir(&dir)?;
    let mut out = Vec::with_capacity(files.len());
    for (i, f) in files.iter().enumerate() {
        let p = dir.join(i.to_string());
        std::fs::write(&p, f.content.as_bytes()).map_err(|e| format!("{}: {e}", p.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644))
                .map_err(|e| format!("{}: {e}", p.display()))?;
        }
        out.push((p, f));
    }
    Ok(out)
}

/// Removes file mounts of other deployments than `keep` (their containers are gone).
pub fn prune_files(resource: &str, keep: Option<&str>) {
    let Ok(root) = files_root(resource) else { return };
    let keep = keep.map(str::to_ascii_lowercase);
    let Ok(rd) = std::fs::read_dir(&root) else { return };
    for e in rd.flatten() {
        if Some(e.file_name().to_string_lossy().as_ref()) != keep.as_deref() {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// Removes every file mount of an application (it has no container left: `AppAction` remove, `VolumeRemove`). File
/// contents may be secret: they do not outlive the application on the server.
pub fn remove_files(resource: &str) {
    if let Ok(root) = files_root(resource) {
        let _ = std::fs::remove_dir_all(root);
    }
}

/// Mounts of a container: its volumes and written files.
pub fn mounts(resource: &str, volumes: &[VolumeMount], files: &[(PathBuf, &FileMount)]) -> Vec<Mount> {
    let mut m: Vec<Mount> = volumes
        .iter()
        .map(|v| Mount {
            typ: Some(MountType::VOLUME),
            source: Some(volume_name(resource, &v.name)),
            target: Some(v.path.clone()),
            ..Default::default()
        })
        .collect();
    m.extend(files.iter().map(|(p, f)| Mount {
        typ: Some(MountType::BIND),
        source: Some(p.to_string_lossy().into_owned()),
        target: Some(f.path.clone()),
        read_only: Some(true),
        ..Default::default()
    }));
    m
}

/// Paths an image declares as volumes (`VOLUME`) that no mount of the container is at: Docker gives each an
/// anonymous volume, removed with the container. A mount at a parent path does not cover a declared path (Docker
/// still mounts an anonymous volume there, over it).
pub fn anonymous_paths<'a>(declared: &'a [String], mounted: &[&str]) -> Vec<&'a str> {
    let norm = |p: &str| p.trim_end_matches('/').to_string();
    let mounted: BTreeSet<String> = mounted.iter().map(|p| norm(p)).collect();
    let mut out: Vec<&str> = declared.iter().map(String::as_str).filter(|p| !mounted.contains(&norm(p))).collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The deployment log's warning for an anonymous volume at `path` (of `service`, in a Compose application).
pub fn anonymous_warning(service: Option<&str>, path: &str) -> String {
    let of = service.map(|s| format!("service {s}: ")).unwrap_or_default();
    format!(
        "Warning: {of}{path} is an anonymous volume: its data is deleted with the container when the next deployment \
         replaces it (mount a volume of the application at exactly {path} to keep it)"
    )
}

/// An external volume a Compose file names (`owd-<resource>-…` or `owd-<resource>_…`, see
/// [`crate::project`]): the application's own or one made by hand, never one labelled for another resource, such as
/// a preview `<resource>-pr<n>`, whose volumes share the application's prefix.
pub fn check_external(project: &str, name: &str, labels: &HashMap<String, String>) -> Result<(), String> {
    let other = labels.get(LABEL_RESOURCE).is_some_and(|r| crate::docker::app_prefix(r) != project)
        || labels.get(COMPOSE_PROJECT).is_some_and(|p| p != project);
    match other {
        true => Err(format!("the external volume {name} belongs to another application or preview: refused")),
        false => Ok(()),
    }
}

/// `VolumeRemove`: the application's volumes (all, or the named ones) and, with all of them, its files and its
/// Compose project's volumes.
pub async fn remove(resource: &str, names: Option<&[String]>) -> Result<Value, String> {
    if !valid_id(resource) {
        return Err("invalid resource id".into());
    }
    let d = client()?;
    if !app_containers(&d, resource).await?.is_empty() {
        return Err("the application still has containers: remove them first".into());
    }
    let mut filters = vec![format!("{LABEL_RESOURCE}={resource}")];
    if names.is_none() {
        filters.push(format!("{COMPOSE_PROJECT}=owd-{}", resource.to_ascii_lowercase()));
    }
    // Every volume is checked before any is removed: one that carries the labels without being the application's
    // refuses the whole command.
    let mut doomed = Vec::new();
    for f in filters {
        let opts =
            ListVolumesOptionsBuilder::default().filters(&HashMap::from([("label".to_string(), vec![f])])).build();
        let list = d.list_volumes(Some(opts)).await.map_err(|e| format!("docker volume ls: {}", message(&e)))?;
        for v in list.volumes.unwrap_or_default() {
            let label = v.labels.get(LABEL_VOLUME).map(String::as_str).unwrap_or_default();
            if names.is_some_and(|n| !n.iter().any(|n| n == label)) {
                continue;
            }
            check_volume(resource, &v.name, Some(&v.labels))?;
            if names.is_some() && v.name != volume_name(resource, label) {
                return Err(format!(
                    "volume {} is not the volume {label} of {resource}: refusing to remove it",
                    v.name
                ));
            }
            if !doomed.contains(&v.name) {
                doomed.push(v.name);
            }
        }
    }
    let mut removed = Vec::new();
    for name in doomed {
        match d.remove_volume(&name, None::<bollard::query_parameters::RemoveVolumeOptions>).await {
            Ok(()) => removed.push(name),
            Err(e) if is_not_found(&e) => {}
            Err(e) => return Err(format!("remove volume {name}: {}", message(&e))),
        }
    }
    if names.is_none() {
        remove_files(resource);
    }
    removed.sort();
    Ok(json!({ "removed": removed }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vol(name: &str, path: &str, service: Option<&str>) -> VolumeMount {
        VolumeMount { name: name.into(), path: path.into(), service: service.map(Into::into) }
    }

    #[test]
    fn mounts_are_validated() {
        assert!(validate(&[vol("data", "/var/lib/data", None)], &[], false).is_ok());
        for bad in [
            vol("Data", "/d", None),
            vol("a/b", "/d", None),
            vol("data", "relative", None),
            vol("data", "/", None),
            vol("data", "/a/../etc", None),
            vol("data", "/d:/host", None),
        ] {
            assert!(validate(std::slice::from_ref(&bad), &[], false).is_err(), "{bad:?}");
        }
        let f =
            |p: &str, s: Option<&str>| FileMount { path: p.into(), content: "x".into(), service: s.map(Into::into) };
        assert!(validate(&[vol("data", "/d", None)], &[f("/d", None)], false).is_err(), "same target twice");
        assert!(validate(&[vol("data", "/d", None)], &[], true).is_err(), "Compose mounts name their service");
        assert!(validate(&[vol("data", "/d", Some("db"))], &[f("/d", Some("web"))], true).is_ok());
    }

    #[test]
    fn image_volumes_without_a_mount_at_their_path_are_anonymous() {
        let declared = vec!["/var/lib/postgresql/data".to_string(), "/cache/".to_string(), "/srv".to_string()];
        // A mount at a parent path does not cover a declared path; a trailing slash does not matter.
        assert_eq!(
            anonymous_paths(&declared, &["/var/lib/postgresql", "/cache"]),
            ["/srv", "/var/lib/postgresql/data"]
        );
        assert!(anonymous_paths(&declared, &["/var/lib/postgresql/data/", "/cache", "/srv"]).is_empty());
        assert!(anonymous_warning(Some("db"), "/srv").starts_with("Warning: service db: /srv is an anonymous volume"));
    }

    #[test]
    fn external_volumes_labelled_for_another_resource_are_refused() {
        let labels = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        };
        let p = "owd-app_01c";
        assert!(check_external(p, "owd-app_01c-data", &labels(&[(LABEL_RESOURCE, "app_01C")])).is_ok());
        assert!(check_external(p, "owd-app_01c_db", &labels(&[(COMPOSE_PROJECT, p)])).is_ok());
        assert!(check_external(p, "owd-app_01c-manual", &labels(&[])).is_ok(), "made by hand");
        // A preview's volumes share the application's prefix.
        assert!(check_external(p, "owd-app_01c-pr3-data", &labels(&[(LABEL_RESOURCE, "app_01C-pr3")])).is_err());
        assert!(check_external(p, "owd-app_01c-pr3_db", &labels(&[(COMPOSE_PROJECT, "owd-app_01c-pr3")])).is_err());
    }
}
