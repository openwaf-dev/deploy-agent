//! Day-to-day operations on an application's containers and images: start, stop, restart, remove, state, logs and
//! image pruning. Every lookup goes through the resource label (containers) or the application's repository
//! (images), so a command for one application never touches another's containers.

use std::collections::{HashMap, HashSet};

use bollard::Docker;
use bollard::container::LogOutput;
use bollard::models::ImageSummary;
use bollard::query_parameters::{
    ListImagesOptionsBuilder, LogsOptionsBuilder, RemoveImageOptionsBuilder, StopContainerOptionsBuilder,
};
use deploy_proto::msg::{AppActionKind, AppState, ContainerState, LABEL_DEPLOYMENT, LABEL_RESOURCE, LogStream};
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::CANCELLED;
use crate::compose::service_of;
use crate::docker::{
    COMPOSE_PROJECT, app_containers, app_repository, check_network, client, is_not_found, is_running, message,
    remove_container, valid_id,
};
use crate::events::{Events, Lines};

fn check(resource: &str) -> Result<(), String> {
    if valid_id(resource) { Ok(()) } else { Err("invalid resource id".into()) }
}

pub async fn status(resource: &str) -> Result<AppState, String> {
    check(resource)?;
    state(&client()?, resource).await
}

async fn state(d: &Docker, resource: &str) -> Result<AppState, String> {
    let mut containers = Vec::new();
    for c in app_containers(d, resource).await? {
        let id = c.id.unwrap_or_default();
        let started_at = match d.inspect_container(&id, None).await {
            Ok(i) => i.state.and_then(|s| s.started_at).filter(|s| !s.starts_with("0001-")),
            Err(e) if is_not_found(&e) => continue,
            Err(e) => return Err(format!("inspect {id}: {}", message(&e))),
        };
        containers.push(ContainerState {
            deployment: c.labels.as_ref().and_then(|l| l.get(LABEL_DEPLOYMENT)).cloned(),
            image: c.image.unwrap_or_default(),
            state: c.state.map(|s| s.to_string()).unwrap_or_default(),
            health: c.health.and_then(|h| h.status).map(|s| s.to_string()).filter(|s| !s.is_empty() && s != "none"),
            started_at,
            id,
        });
    }
    Ok(AppState { containers })
}

pub async fn action(resource: &str, action: AppActionKind) -> Result<AppState, String> {
    check(resource)?;
    let d = client()?;
    let list = app_containers(&d, resource).await?;
    // The newest container is the current deployment; older ones only exist while a deployment switches. A Compose
    // application's current containers are all of them, one or more per service.
    let compose = list.iter().any(|c| service_of(c).is_some());
    let current: Vec<String> = match compose {
        true => list.iter().filter_map(|c| c.id.clone()).collect(),
        false => list.first().and_then(|c| c.id.clone()).into_iter().collect(),
    };
    match action {
        AppActionKind::Start => {
            if current.is_empty() {
                return Err("the application has no container: deploy it first".into());
            }
            for id in &current {
                match d.start_container(id, None).await {
                    Ok(()) => {}
                    // 304: already running.
                    Err(bollard::errors::Error::DockerResponseServerError { status_code: 304, .. }) => {}
                    Err(e) => return Err(format!("start: {}", message(&e))),
                }
            }
        }
        AppActionKind::Stop => {
            for c in list.iter().filter(|c| is_running(c)) {
                let id = c.id.as_deref().unwrap_or_default();
                let opts = StopContainerOptionsBuilder::default().t(15).build();
                d.stop_container(id, Some(opts)).await.map_err(|e| format!("stop: {}", message(&e)))?;
            }
        }
        AppActionKind::Restart => {
            if current.is_empty() {
                return Err("the application has no container: deploy it first".into());
            }
            for id in &current {
                let opts = bollard::query_parameters::RestartContainerOptionsBuilder::default().t(15).build();
                d.restart_container(id, Some(opts)).await.map_err(|e| format!("restart: {}", message(&e)))?;
            }
        }
        AppActionKind::Remove => {
            // Checked before anything goes: a network that is not the project's refuses the whole removal.
            let networks = compose_networks(&d, resource).await?;
            crate::router::forget(resource).await?;
            for c in &list {
                remove_container(&d, c.id.as_deref().unwrap_or_default()).await?;
            }
            for (id, name) in networks {
                match d.remove_network(&id).await {
                    Ok(()) => {}
                    Err(e) if is_not_found(&e) => {}
                    Err(e) => return Err(format!("remove network {name}: {}", message(&e))),
                }
            }
            // Like a prune that keeps nothing: a pulled image only loses the application's tags, an image someone
            // else tagged keeps them.
            for (img, ours) in images(&d, resource).await? {
                if img.repo_tags.is_empty() {
                    remove_image(&d, &img.id, false).await?;
                }
                for t in &ours {
                    remove_image(&d, t, false).await?;
                }
            }
        }
    }
    state(&d, resource).await
}

/// Networks Compose created for the application's project (its default network and the file's own), as (id,
/// name); one carrying the project's label without its name is refused.
async fn compose_networks(d: &Docker, resource: &str) -> Result<Vec<(String, String)>, String> {
    let filter = format!("{COMPOSE_PROJECT}={}", crate::compose::project(resource));
    let opts = bollard::query_parameters::ListNetworksOptionsBuilder::default()
        .filters(&HashMap::from([("label".to_string(), vec![filter])]))
        .build();
    let list = d.list_networks(Some(opts)).await.map_err(|e| format!("docker network ls: {}", message(&e)))?;
    let mut out = Vec::new();
    for n in list {
        let name = n.name.unwrap_or_default();
        check_network(resource, &name, n.labels.as_ref())?;
        out.push((n.id.unwrap_or_default(), name));
    }
    Ok(out)
}

/// Images of an application: built ones carry its label, pulled ones only its repository's tags.
async fn images(d: &Docker, resource: &str) -> Result<Vec<(ImageSummary, Vec<String>)>, String> {
    let repo = app_repository(resource);
    let mut by_id: HashMap<String, ImageSummary> = HashMap::new();
    for filter in [("label", format!("{LABEL_RESOURCE}={resource}")), ("reference", repo.clone())] {
        let filters = HashMap::from([(filter.0.to_string(), vec![filter.1])]);
        let opts = ListImagesOptionsBuilder::default().all(false).filters(&filters).build();
        for i in d.list_images(Some(opts)).await.map_err(|e| format!("docker images: {}", message(&e)))? {
            by_id.insert(i.id.clone(), i);
        }
    }
    let prefix = format!("{repo}:");
    Ok(by_id
        .into_values()
        .map(|i| {
            let ours = i.repo_tags.iter().filter(|t| t.starts_with(&prefix)).cloned().collect();
            (i, ours)
        })
        .collect())
}

async fn remove_image(d: &Docker, reference: &str, force: bool) -> Result<(), String> {
    let opts = RemoveImageOptionsBuilder::default().force(force).build();
    match d.remove_image(reference, Some(opts), None).await {
        Ok(_) => Ok(()),
        Err(e) if is_not_found(&e) => Ok(()),
        Err(e) => Err(format!("remove image {reference}: {}", message(&e))),
    }
}

/// Removes the application's images not tagged in `keep` and not used by any container. A pulled image only loses
/// the application's tags (its own, like `nginx:1.29`, stay); a built one goes once untagged.
pub async fn prune(resource: &str, keep: &[String]) -> Result<Value, String> {
    check(resource)?;
    let d = client()?;
    let keep: HashSet<&str> = keep.iter().map(String::as_str).collect();
    let all = d
        .list_containers(Some(bollard::query_parameters::ListContainersOptionsBuilder::default().all(true).build()))
        .await
        .map_err(|e| format!("docker ps: {}", message(&e)))?;
    let used: HashSet<String> = all.into_iter().filter_map(|c| c.image_id).collect();
    let mut removed = Vec::new();
    for (img, ours) in images(&d, resource).await? {
        if used.contains(&img.id) || ours.iter().any(|t| keep.contains(t.as_str())) {
            continue;
        }
        if ours.is_empty() {
            // Untagged leftover of an earlier build (its tag moved on): only its label ties it to the application.
            if img.repo_tags.is_empty() {
                remove_image(&d, &img.id, false).await?;
                removed.push(img.id.clone());
            }
            continue;
        }
        for t in &ours {
            remove_image(&d, t, false).await?;
            removed.push(t.clone());
        }
    }
    removed.sort();
    Ok(json!({ "removed": removed }))
}

/// Logs of the current container (of a Compose application: of `service`, else its newest container): the last
/// `tail` lines (since `since`), then new lines while `follow`, until cancelled. Each line starts with Docker's
/// RFC 3339 timestamp.
pub async fn logs(
    resource: &str,
    tail: u32,
    follow: bool,
    since: Option<i64>,
    service: Option<&str>,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<Value, String> {
    check(resource)?;
    let d = client()?;
    let list: Vec<_> = app_containers(&d, resource)
        .await?
        .into_iter()
        .filter(|c| service.is_none_or(|s| service_of(c) == Some(s)))
        .collect();
    let current = list.iter().find(|c| is_running(c)).or(list.first()).and_then(|c| c.id.clone());
    let id = current.ok_or_else(|| match service {
        Some(s) => format!("the service {s} has no container"),
        None => "the application has no container".to_string(),
    })?;
    let mut opts =
        LogsOptionsBuilder::default().stdout(true).stderr(true).timestamps(true).follow(follow).tail(&tail.to_string());
    if let Some(s) = since {
        opts = opts.since(s.clamp(0, i64::from(i32::MAX)) as i32);
    }
    let mut s = d.logs(&id, Some(opts.build()));
    let (mut out, mut err) = (Lines::default(), Lines::default());
    let mut count = 0u64;
    loop {
        let item = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(CANCELLED.into()),
            i = s.next() => i,
        };
        let Some(item) = item else { break };
        let (stream, buf, chunk) = match item.map_err(|e| format!("logs: {}", message(&e)))? {
            LogOutput::StdErr { message } => (LogStream::Stderr, &mut err, message),
            LogOutput::StdOut { message } | LogOutput::Console { message } => (LogStream::Stdout, &mut out, message),
            LogOutput::StdIn { .. } => continue,
        };
        for l in buf.push(&chunk) {
            count += 1;
            ev.line(stream, l).await;
        }
    }
    for (stream, buf) in [(LogStream::Stdout, &mut out), (LogStream::Stderr, &mut err)] {
        if let Some(l) = buf.finish() {
            count += 1;
            ev.line(stream, l).await;
        }
    }
    Ok(json!({ "lines": count }))
}
