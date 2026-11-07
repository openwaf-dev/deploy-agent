//! Docker Engine through its local socket (bollard). Only typed calls; never a shell.

use std::collections::HashMap;
use std::time::Duration;

use bollard::Docker;
use bollard::errors::Error;
use bollard::models::ContainerSummary;
use bollard::query_parameters::{
    CreateImageOptionsBuilder, ListContainersOptionsBuilder, RemoveContainerOptionsBuilder,
    UploadToContainerOptionsBuilder,
};
use deploy_proto::msg::{DockerInfo, LABEL_RESOURCE};
use futures_util::StreamExt;
use serde_json::{Value, json};

use crate::events::Events;

/// Label Docker Compose puts on everything of a project, and on containers the service they run.
pub const COMPOSE_PROJECT: &str = "com.docker.compose.project";
pub const COMPOSE_SERVICE: &str = "com.docker.compose.service";

/// Label on helper containers (Git clones), with the resource they work for. Kept apart from [`LABEL_RESOURCE`] so a
/// helper never counts as one of the application's containers.
pub const LABEL_HELPER: &str = "dev.openwaf.deploy.helper";

/// Time to wait for the Engine's answer to one request (not for a whole build or log stream: those are bodies).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(600);

pub fn client() -> Result<Docker, String> {
    Docker::connect_with_local_defaults().map(|d| d.with_timeout(REQUEST_TIMEOUT)).map_err(|e| format!("docker: {e}"))
}

/// Pulls `image` unless the Engine already has it (helper and router images are pinned, so present means current).
pub async fn ensure_image(d: &Docker, image: &str, ev: Option<&Events>) -> Result<(), String> {
    if d.inspect_image(image).await.is_ok() {
        return Ok(());
    }
    if let Some(ev) = ev {
        ev.system(format!("Pulling {image}")).await;
    }
    let mut s = d.create_image(Some(CreateImageOptionsBuilder::default().from_image(image).build()), None, None);
    while let Some(r) = s.next().await {
        let info = r.map_err(|e| format!("pull {image}: {}", message(&e)))?;
        if let Some(e) = info.error_detail {
            return Err(format!("pull {image}: {}", e.message.unwrap_or_default()));
        }
    }
    Ok(())
}

/// A file to put into a container with [`upload`].
pub struct File<'a> {
    pub path: &'a str,
    pub data: &'a [u8],
    pub mode: u32,
}

/// Writes files into a container (created or running) under `dir`, which must exist in it.
pub async fn upload(d: &Docker, container: &str, dir: &str, files: &[File<'_>]) -> Result<(), String> {
    let mut b = tar::Builder::new(Vec::new());
    for f in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(f.data.len() as u64);
        h.set_mode(f.mode);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, f.path, f.data).map_err(|e| format!("archive {}: {e}", f.path))?;
    }
    let body = b.into_inner().map_err(|e| e.to_string())?;
    let opts = UploadToContainerOptionsBuilder::default().path(dir).build();
    d.upload_to_container(container, Some(opts), bollard::body_full(body.into()))
        .await
        .map_err(|e| format!("copy into {container}: {}", message(&e)))
}

pub fn is_not_found(e: &Error) -> bool {
    matches!(e, Error::DockerResponseServerError { status_code: 404, .. })
}

/// The Engine's message for an error, without bollard's wrapping.
pub fn message(e: &Error) -> String {
    match e {
        Error::DockerResponseServerError { message, .. } => message.clone(),
        Error::DockerStreamError { error } => error.clone(),
        e => e.to_string(),
    }
}

pub async fn info() -> Result<DockerInfo, String> {
    let d = client()?;
    let v = d.version().await.map_err(|e| format!("docker version: {e}"))?;
    let i = d.info().await.map_err(|e| format!("docker info: {e}"))?;
    Ok(DockerInfo {
        version: v.version.unwrap_or_default(),
        api_version: v.api_version.unwrap_or_default(),
        containers_running: i.containers_running.unwrap_or(0).max(0) as u64,
        containers_total: i.containers.unwrap_or(0).max(0) as u64,
        images: i.images.unwrap_or(0).max(0) as u64,
    })
}

pub async fn running() -> Result<u64, String> {
    let i = client()?.info().await.map_err(|e| format!("docker info: {e}"))?;
    Ok(i.containers_running.unwrap_or(0).max(0) as u64)
}

/// Containers of the engine: id, names, image, state, status and labels of OpenWAF Deploy.
pub async fn containers(managed_only: bool) -> Result<Value, String> {
    let d = client()?;
    let mut opts = ListContainersOptionsBuilder::default().all(true);
    if managed_only {
        let mut filters = HashMap::new();
        filters.insert("label".to_string(), vec![LABEL_RESOURCE.to_string()]);
        opts = opts.filters(&filters);
    }
    let list = d.list_containers(Some(opts.build())).await.map_err(|e| format!("docker ps: {e}"))?;
    Ok(Value::Array(
        list.into_iter()
            .map(|c| {
                let id = c.id.unwrap_or_default();
                let labels = c.labels.unwrap_or_default();
                json!({
                    "id": &id[..id.len().min(12)],
                    "names": c.names.unwrap_or_default().into_iter().map(|n| n.trim_start_matches('/').to_string()).collect::<Vec<_>>(),
                    "image": c.image.unwrap_or_default(),
                    "state": c.state.map(|s| s.to_string()).unwrap_or_default(),
                    "status": c.status.unwrap_or_default(),
                    "resource": labels.get(LABEL_RESOURCE),
                })
            })
            .collect(),
    ))
}

/// Containers carrying `label=value`, newest first.
pub async fn labelled(d: &Docker, label: &str, value: &str) -> Result<Vec<ContainerSummary>, String> {
    let mut filters = HashMap::new();
    filters.insert("label".to_string(), vec![format!("{label}={value}")]);
    let opts = ListContainersOptionsBuilder::default().all(true).filters(&filters).build();
    let mut list = d.list_containers(Some(opts)).await.map_err(|e| format!("docker ps: {}", message(&e)))?;
    list.sort_by_key(|c| std::cmp::Reverse(c.created.unwrap_or(0)));
    Ok(list)
}

/// Containers of an application, newest first. The resource label alone does not make a container the
/// application's: one that is not also named (or composed) as its containers is refused, with the whole command.
pub async fn app_containers(d: &Docker, resource: &str) -> Result<Vec<ContainerSummary>, String> {
    let list = labelled(d, LABEL_RESOURCE, resource).await?;
    for c in &list {
        check_container(resource, c.names.as_deref().unwrap_or_default(), c.labels.as_ref())?;
    }
    Ok(list)
}

/// What every Docker object of an application is named after: `owd-<resource lowercased>` (also its Compose
/// project).
pub fn app_prefix(resource: &str) -> String {
    format!("owd-{}", resource.to_ascii_lowercase())
}

fn label<'a>(labels: Option<&'a HashMap<String, String>>, key: &str) -> Option<&'a str> {
    labels?.get(key).map(String::as_str)
}

/// A container commands for `resource` may act on: it carries the application's label and is named
/// `owd-<resource>-…` (its deployments) or belongs to its Compose project `owd-<resource>`.
pub fn check_container(
    resource: &str,
    names: &[String],
    labels: Option<&HashMap<String, String>>,
) -> Result<(), String> {
    let prefix = app_prefix(resource);
    let named = names.iter().any(|n| n.trim_start_matches('/').starts_with(&format!("{prefix}-")));
    let composed = label(labels, COMPOSE_PROJECT) == Some(prefix.as_str());
    if label(labels, LABEL_RESOURCE) == Some(resource) && (named || composed) {
        return Ok(());
    }
    let name = names.first().map_or("(unnamed)", |n| n.trim_start_matches('/'));
    Err(format!(
        "container {name} is not one of the containers of {resource} (named {prefix}-… or of the Compose project \
         {prefix}, with its label): refusing to act on it"
    ))
}

/// A volume of `resource`: one of its named volumes (`owd-<resource>-<name>`, its label) or of its Compose
/// project (`owd-<resource>_<name>`, the project's label).
pub fn check_volume(resource: &str, name: &str, labels: Option<&HashMap<String, String>>) -> Result<(), String> {
    let prefix = app_prefix(resource);
    let ours = (name.starts_with(&format!("{prefix}-")) && label(labels, LABEL_RESOURCE) == Some(resource))
        || (name.starts_with(&format!("{prefix}_")) && label(labels, COMPOSE_PROJECT) == Some(prefix.as_str()));
    match ours {
        true => Ok(()),
        false => Err(format!(
            "volume {name} is not a volume of {resource} (named {prefix}-… or {prefix}_…, with its label): refusing \
             to remove it"
        )),
    }
}

/// A network of `resource`'s Compose project (`owd-<resource>_<name>`, the project's label).
pub fn check_network(resource: &str, name: &str, labels: Option<&HashMap<String, String>>) -> Result<(), String> {
    let prefix = app_prefix(resource);
    match name.starts_with(&format!("{prefix}_")) && label(labels, COMPOSE_PROJECT) == Some(prefix.as_str()) {
        true => Ok(()),
        false => Err(format!(
            "network {name} is not a network of the Compose project {prefix} (named {prefix}_…): refusing to remove it"
        )),
    }
}

/// An image reference in `resource`'s repository (`owd/<resource>:<tag>`), the only images its commands tag,
/// run or remove.
pub fn check_image(resource: &str, image: &str) -> Result<(), String> {
    let repo = app_repository(resource);
    match split_tag(image) {
        (r, Some(t)) if r == repo && !t.is_empty() => Ok(()),
        _ => Err(format!("image {image:?} is not in the repository of {resource} ({repo}:<tag>): refused")),
    }
}

pub fn is_running(c: &ContainerSummary) -> bool {
    c.state.as_ref().is_some_and(|s| s.to_string() == "running")
}

/// Removes a container, its anonymous volumes included; a container already gone is not an error.
pub async fn remove_container(d: &Docker, id: &str) -> Result<(), String> {
    let opts = RemoveContainerOptionsBuilder::default().force(true).v(true).build();
    match d.remove_container(id, Some(opts)).await {
        Ok(()) => Ok(()),
        Err(e) if is_not_found(&e) => Ok(()),
        Err(e) => Err(format!("remove container {id}: {}", message(&e))),
    }
}

/// Docker repository of an application's images: `owd/<resource lowercased>`.
pub fn app_repository(resource: &str) -> String {
    format!("owd/{}", resource.to_ascii_lowercase())
}

/// Container name of a deployment: `owd-<resource>-<last 8 of the deployment>`, lowercased.
pub fn container_name(resource: &str, deployment: &str) -> String {
    let dep = deployment.to_ascii_lowercase();
    format!("owd-{}-{}", resource.to_ascii_lowercase(), &dep[dep.len().saturating_sub(8)..])
}

/// Splits `repo[:tag]` (the registry may carry a port) into repository and tag.
pub fn split_tag(image: &str) -> (&str, Option<&str>) {
    let name_start = image.rfind('/').map_or(0, |i| i + 1);
    match image[name_start..].rfind(':') {
        Some(i) => (&image[..name_start + i], Some(&image[name_start + i + 1..])),
        None => (image, None),
    }
}

/// An image reference with an explicit tag: the Engine pulls every tag of a repository given without one.
pub fn pull_reference(image: &str) -> String {
    if image.contains('@') || split_tag(image).1.is_some() { image.to_string() } else { format!("{image}:latest") }
}

/// Ids and names are what Docker accepts in names and labels and nothing that could steer a path or a filter.
pub fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_references() {
        assert_eq!(container_name("app_01JABC", "dep_01JXYZ0123456789"), "owd-app_01jabc-23456789");
        assert_eq!(split_tag("owd/app_1:dep_2"), ("owd/app_1", Some("dep_2")));
        assert_eq!(split_tag("registry:5000/team/web"), ("registry:5000/team/web", None));
        assert_eq!(split_tag("registry:5000/team/web:1.2"), ("registry:5000/team/web", Some("1.2")));
        assert_eq!(pull_reference("nginx"), "nginx:latest");
        assert_eq!(pull_reference("registry:5000/web"), "registry:5000/web:latest");
        assert_eq!(pull_reference("nginx@sha256:abc"), "nginx@sha256:abc");
        assert!(valid_id("app_01JABC"));
        assert!(!valid_id("app/../x"));
        assert!(!valid_id(""));
    }

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn containers_are_the_applications_own_only() {
        let own = labels(&[(LABEL_RESOURCE, "app_01J")]);
        let names = |n: &str| vec![format!("/{n}")];
        assert!(check_container("app_01J", &names("owd-app_01j-23456789"), Some(&own)).is_ok());
        let compose = labels(&[(LABEL_RESOURCE, "app_01J"), (COMPOSE_PROJECT, "owd-app_01j")]);
        assert!(
            check_container("app_01J", &names("custom-name"), Some(&compose)).is_ok(),
            "container_name: in Compose"
        );
        // The label alone is not enough: a container someone else labelled, the router, another application's.
        let e = check_container("app_01J", &names("postgres"), Some(&own)).unwrap_err();
        assert!(e.contains("postgres") && e.contains("refusing"), "{e}");
        assert!(check_container("app_01J", &names("owd-router"), Some(&own)).is_err());
        assert!(check_container("app_01J", &names("owd-app_01j0-23456789"), Some(&own)).is_err(), "prefix of another");
        let other = labels(&[(LABEL_RESOURCE, "app_02")]);
        assert!(check_container("app_01J", &names("owd-app_01j-23456789"), Some(&other)).is_err());
        assert!(check_container("app_01J", &names("owd-app_01j-23456789"), None).is_err());
        let wrong_project = labels(&[(LABEL_RESOURCE, "app_01J"), (COMPOSE_PROJECT, "owd-app_02")]);
        assert!(check_container("app_01J", &names("custom-name"), Some(&wrong_project)).is_err());
    }

    #[test]
    fn volumes_networks_and_images_are_the_applications_own_only() {
        let own = labels(&[(LABEL_RESOURCE, "app_01J")]);
        let project = labels(&[(COMPOSE_PROJECT, "owd-app_01j")]);
        assert!(check_volume("app_01J", "owd-app_01j-data", Some(&own)).is_ok());
        assert!(check_volume("app_01J", "owd-app_01j_pgdata", Some(&project)).is_ok());
        assert!(check_volume("app_01J", "owd-router", Some(&own)).is_err(), "the router's configuration");
        assert!(check_volume("app_01J", "pgdata", Some(&project)).is_err(), "a Compose volume renamed with name:");
        assert!(check_volume("app_01J", "owd-app_01j-data", Some(&project)).is_err(), "unlabelled");
        assert!(check_volume("app_01J", "owd-app_02-data", Some(&own)).is_err());
        assert!(check_volume("app_01J", "buildx_buildkit_owd-buildkit0_state", Some(&own)).is_err());

        assert!(check_network("app_01J", "owd-app_01j_default", Some(&project)).is_ok());
        assert!(check_network("app_01J", "owd-0a1b2c3d4e5f", Some(&project)).is_err(), "an environment network");
        assert!(check_network("app_01J", "shared", Some(&project)).is_err());
        assert!(check_network("app_01J", "owd-app_01j_default", Some(&own)).is_err());

        assert!(check_image("app_01J", "owd/app_01j:dep_01x").is_ok());
        for bad in ["nginx:latest", "owd/app_02:dep_1", "owd/app_01j", "owd/app_01j:", "registry/owd/app_01j:x"] {
            assert!(check_image("app_01J", bad).is_err(), "{bad}");
        }
    }
}
