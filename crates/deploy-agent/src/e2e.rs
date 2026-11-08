//! End-to-end checks against a real Docker Engine, driving `execute` exactly as a session does. They change the
//! engine's state (containers, images, volumes, networks, the router; the firewall test also iptables and network
//! namespaces), so they only run when asked:
//!
//! - `OWDEPLOY_TEST_DOCKER=1`: deployments, rolling switch through the router, rollback on a failed health check,
//!   cancel, logs, prune, Railpack and static builds, Compose (and a project deployed by Compose itself, as earlier
//!   agents did), deploy keys, volumes, exec, previews, SBOMs; while builds run, no helper container may have the
//!   Engine's socket or a host path. The agent must reach container addresses and run in the host's PID namespace
//!   (run it on the Docker host, or in a container with `--network host --pid host`), and `OWDEPLOY_AGENT_STATE`
//!   must name a directory at the same path on the Docker host (file mounts are bind mounts of files in it). Builds
//!   go through the build egress proxy, which runs a static Linux build of the agent: `OWDEPLOY_BUILD_PROXY_BINARY`
//!   names one (e.g. `cargo zigbuild --release -p deploy-agent --target aarch64-unknown-linux-musl`, mounted into
//!   the runner). The build egress test needs the Internet (example.com, example.org, localtest.me).
//! - `OWDEPLOY_TEST_CLASSIC_STORE=1`: the tests also check that the Engine runs the classic image store (no
//!   containerd snapshotter), which loads the agent's image archives through their `manifest.json` (the containerd
//!   store through their `index.json`).
//! - `OWDEPLOY_TEST_FIREWALL=1` as well: FirewallSync and the containers' egress guard for real, both families
//!   (root, iptables, ip6tables, iproute2, curl and python3 on the host; the host's interfaces must not start with
//!   `owd`, the prefix of Deploy's bridges). They rewrite the host's firewall: run them against a throwaway dockerd
//!   (as for the classic store below), which has its own network namespace.
//! - `OWDEPLOY_TEST_REGISTRY=1` as well: private registries, with a `registry:2` asking for Basic credentials at
//!   `203.0.113.50:5000` (a documentation address the build egress proxy does not refuse), alone in a network
//!   namespace behind the host (root, iproute2 and nsenter on the host). The Engine must list it in its
//!   `insecure-registries`; while the test runs, the trusted builder's BuildKit configuration lists it as plain HTTP.
//!
//! Requests to the router go to the host's own address (`ip route get`), as its listeners are routed by the agent's
//! DNAT, which does not apply to loopback.
//!
//! Run them one at a time (`--test-threads=1`): they compare the engine's state before and after. From a Mac with
//! colima, run them in a Linux container on the Docker host (an image with Rust, `docker-cli`, `iptables`,
//! `iproute2`, `curl`, `git`, `ssh-keygen` and `apparmor`). colima's Ubuntu restricts unprivileged user namespaces
//! to AppArmor-confined programs, so the agent loads its builders' AppArmor profile: the runner mounts securityfs.
//!
//! ```text
//! docker run --rm --privileged --network host --pid host -v /var/run/docker.sock:/var/run/docker.sock \
//!   -v /var/lib/owdeploy-e2e:/var/lib/owdeploy-e2e -e OWDEPLOY_AGENT_STATE=/var/lib/owdeploy-e2e \
//!   -v "$PWD":/w -w /w -e OWDEPLOY_TEST_DOCKER=1 -e OWDEPLOY_TEST_FIREWALL=1 <runner image> sh -c \
//!   'mount -t securityfs securityfs /sys/kernel/security && cargo test -p deploy-agent e2e -- --test-threads=1'
//! ```
//!
//! The Engine of colima uses the containerd image store. For the classic store, run the tests against a throwaway
//! dockerd started with it disabled, sharing its network and PID namespaces, socket and state directory (without
//! `features`, the same dockerd runs the containerd store; `insecure-registries` is for `OWDEPLOY_TEST_REGISTRY`):
//!
//! ```text
//! docker run -d --name owd-e2e-dind --privileged -v owd-e2e-dind-sock:/var/run -v owd-e2e-dind-lib:/var/lib/docker \
//!   -v owd-e2e-dind-state:/var/lib/owdeploy-e2e -e DOCKER_TLS_CERTDIR= --entrypoint sh docker:29.9.3-dind -c \
//!   'mkdir -p /etc/docker && echo "{\"features\":{\"containerd-snapshotter\":false}, \
//!    \"insecure-registries\":[\"203.0.113.50:5000\"]}" > /etc/docker/daemon.json \
//!    && exec dockerd-entrypoint.sh dockerd --host=unix:///var/run/docker.sock'
//! docker run --rm --privileged --network container:owd-e2e-dind --pid container:owd-e2e-dind \
//!   -v owd-e2e-dind-sock:/var/run -v owd-e2e-dind-state:/var/lib/owdeploy-e2e \
//!   -e OWDEPLOY_AGENT_STATE=/var/lib/owdeploy-e2e -v "$PWD":/w -w /w -e OWDEPLOY_TEST_DOCKER=1 \
//!   -e OWDEPLOY_TEST_CLASSIC_STORE=1 <runner image> cargo test -p deploy-agent e2e -- --test-threads=1
//! ```

use std::collections::BTreeSet;
use std::process::Command as Proc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use deploy_proto::msg::{
    AppActionKind, AppDeploy, AppState, BuildEgress, BuildPack, BuildSpec, ComposeDeploy, ComposeOutput, ComposeSource,
    DeployOutput, EgressDecision, EgressMode, Event, ExecOutput, ExecSpec, FileMount, FirewallRules, HealthCheck,
    LABEL_ENVIRONMENT, LogStream, Op, Outcome, RegistryAuth, ResourceRoutes, Route, RouterConfig, RouterState, RunSpec,
    Source, SshAuth, Step, VolumeMount,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::events::{Events, Outgoing};

const NETWORK: &str = "owd-e2etest0000";

fn enabled(var: &str) -> bool {
    let on = std::env::var(var).as_deref() == Ok("1");
    if !on {
        eprintln!("skipped: set {var}=1 to run against the local Docker Engine");
        return false;
    }
    let state = std::env::var("OWDEPLOY_AGENT_STATE").unwrap_or_default();
    assert!(state.starts_with('/'), "set OWDEPLOY_AGENT_STATE to a directory at the same path on the Docker host");
    if std::env::var("OWDEPLOY_TEST_CLASSIC_STORE").as_deref() == Ok("1") {
        let status = docker_cli(&["info", "-f", "{{json .DriverStatus}}"]);
        assert!(!status.contains("io.containerd.snapshotter"), "the Engine uses the containerd image store: {status}");
    }
    true
}

struct Run {
    outcome: Outcome,
    events: Vec<Event>,
}

impl Run {
    fn ok<T: serde::de::DeserializeOwned>(&self) -> T {
        match &self.outcome {
            Outcome::Ok { output } => serde_json::from_value(output.clone()).unwrap(),
            o => panic!("expected success, got {o:?}; log:\n{}", self.log().join("\n")),
        }
    }

    fn err(&self) -> String {
        match &self.outcome {
            Outcome::Error { message } => message.clone(),
            o => panic!("expected an error, got {o:?}"),
        }
    }

    fn steps(&self) -> Vec<Step> {
        self.events.iter().filter_map(|e| if let Event::Step { step, .. } = e { Some(*step) } else { None }).collect()
    }

    fn log(&self) -> Vec<String> {
        self.lines(None)
    }

    fn lines(&self, only: Option<LogStream>) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::Log { stream, lines, .. } if only.is_none_or(|o| o == *stream) => Some(lines.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }
}

async fn exec(op: Op, cancel: CancellationToken) -> Run {
    let (tx, mut rx) = mpsc::channel(1024);
    let collect = tokio::spawn(async move {
        let mut v = Vec::new();
        while let Some(o) = rx.recv().await {
            match o {
                Outgoing::Event(e) => v.push(e.event),
                Outgoing::Result(_) => unreachable!("results are sent by the session"),
            }
        }
        v
    });
    let (ev, batcher) = Events::start("e2e".into(), tx);
    let outcome = crate::execute(op, &ev, &cancel).await;
    drop(ev);
    batcher.await.unwrap();
    Run { outcome, events: collect.await.unwrap() }
}

async fn run(op: Op) -> Run {
    exec(op, CancellationToken::new()).await
}

fn app_deploy(
    resource: &str,
    deployment: &str,
    source: Source,
    port: u16,
    publish: Option<u16>,
    health: Option<&str>,
) -> AppDeploy {
    AppDeploy {
        resource: resource.into(),
        deployment: deployment.into(),
        network: NETWORK.into(),
        alias: "web".into(),
        source,
        build: None,
        run: RunSpec {
            image_tag: format!("owd/{}:{}", resource.to_ascii_lowercase(), deployment.to_ascii_lowercase()),
            env: [("GREETING".to_string(), "hello".to_string())].into(),
            port,
            publish,
            health: health.map(|p| HealthCheck { path: p.into(), interval_secs: 1, timeout_secs: 2, retries: 5 }),
            command: None,
            memory_bytes: Some(256 << 20),
            cpus: Some(0.5),
            labels: [(LABEL_ENVIRONMENT.to_string(), "e2e-env".to_string())].into(),
            volumes: vec![],
            files: vec![],
        },
        // A phase-2 control plane's command: routed by `publish`.
        routes: None,
        drain_secs: Some(1),
    }
}

fn deploy(resource: &str, deployment: &str, source: Source, port: u16, publish: u16, health: Option<&str>) -> Op {
    Op::DeployApp(app_deploy(resource, deployment, source, port, Some(publish), health))
}

fn image(name: &str) -> Source {
    Source::Image { image: name.into(), auth: None }
}

fn git(url: &str, reference: &str) -> Source {
    Source::Git { url: url.into(), reference: reference.into(), auth: None, ssh: None, commit: None }
}

fn build(pack: BuildPack) -> BuildSpec {
    BuildSpec {
        context: ".".into(),
        dockerfile: "Dockerfile".into(),
        args: Default::default(),
        target: None,
        no_cache: false,
        pack,
        install_command: None,
        build_command: None,
        start_command: None,
        publish_dir: None,
        spa: false,
        untrusted: false,
        egress: None,
        registry_auth: Vec::new(),
    }
}

/// A busybox web server answering `text` on port 8080, from an image this test tags.
fn busybox_site(text: &str) -> Option<Vec<String>> {
    Some(vec![
        "sh".into(),
        "-c".into(),
        format!("mkdir -p /www && echo {text} > /www/index.html && exec httpd -f -p 8080 -h /www"),
    ])
}

async fn remove_app(resource: &str) {
    run(Op::AppAction { resource: resource.into(), action: AppActionKind::Remove }).await.ok::<AppState>();
}

async fn status(resource: &str) -> AppState {
    run(Op::AppStatus { resource: resource.into() }).await.ok()
}

async fn http(url: &str) -> Result<(u16, String), String> {
    http_host(url, None).await
}

/// The host's own address: the router's listeners answer on it, not on loopback (see `router`).
static HOST_ADDR: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    let out = Proc::new("ip").args(["-4", "route", "get", "192.0.2.1"]).output().expect("ip route");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut words = text.split_whitespace();
    words.find(|w| *w == "src").and_then(|_| words.next()).expect("a source address").to_string()
});

/// Requests written for 127.0.0.1 go to the host's own address.
fn on_host(url: &str) -> String {
    url.replacen("127.0.0.1", &HOST_ADDR, 1)
}

async fn http_host(url: &str, host: Option<&str>) -> Result<(u16, String), String> {
    let c = reqwest::Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
    let mut req = c.get(on_host(url));
    if let Some(h) = host {
        req = req.header("Host", h);
    }
    let r = req.send().await.map_err(|e| e.to_string())?;
    Ok((r.status().as_u16(), r.text().await.unwrap_or_default()))
}

fn docker_cli(args: &[&str]) -> String {
    let o = Proc::new("docker").args(args).output().expect("docker CLI");
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn docker_ok(args: &[&str]) {
    let o = Proc::new("docker").args(args).output().expect("docker CLI");
    assert!(o.status.success(), "docker {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

#[tokio::test]
async fn image_deploy_switch_rollback_and_logs() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let app = "app_e2eimage";
    remove_app(app).await;
    // Without SBOMs cached, so each source of a pulled image's SBOM is exercised below.
    let cache = std::path::Path::new(&std::env::var("OWDEPLOY_AGENT_STATE").unwrap()).join("sbom");
    let _ = std::fs::remove_dir_all(&cache);

    // First deployment: pulled image, published port (a router listener), health check.
    let first = run(deploy(app, "dep_E2EA0001", image("nginx:1.29-alpine"), 80, 28081, Some("/"))).await;
    let out1: DeployOutput = first.ok();
    // A pulled image's SBOM: the registry's SPDX attestation (official images have one).
    assert_sbom(&first, &out1.image_id, None);
    assert!(first.log().iter().any(|l| l.contains("(registry attestation, ")), "{:?}", first.log());
    assert_eq!(first.steps(), [Step::Pulling, Step::Starting, Step::HealthCheck, Step::Switching, Step::Cleaning]);
    assert_eq!(out1.image, "owd/app_e2eimage:dep_e2ea0001");
    assert!(first.lines(Some(LogStream::System)).iter().any(|l| l.starts_with("Health check passed")));
    assert_eq!(http("http://127.0.0.1:28081/").await.unwrap().0, 200);
    // The router names neither itself nor the application's server (nginx sends `Server: nginx`).
    let r = reqwest::get(on_host("http://127.0.0.1:28081/")).await.unwrap();
    let seen: Vec<_> = ["via", "server"].into_iter().filter(|h| r.headers().contains_key(*h)).collect();
    assert!(seen.is_empty(), "fingerprint headers {seen:?}: {:?}", r.headers());
    let s = status(app).await;
    assert_eq!(s.containers.len(), 1);
    assert_eq!(s.containers[0].state, "running");
    assert_eq!(s.containers[0].deployment.as_deref(), Some("dep_E2EA0001"));
    // The container publishes nothing: the router serves the port (above).
    assert_eq!(docker_cli(&["port", &out1.container_id]), "");

    // Redeploy: the new container replaces the old one, which is removed. The image is the server's own: without a
    // cached SBOM, syft generates it from the image the agent exports, in a helper without network.
    let _ = std::fs::remove_dir_all(&cache);
    let watch = HelperWatch::start();
    let second =
        run(deploy(app, "dep_E2EA0002", Source::Local { image: out1.image.clone() }, 80, 28081, Some("/"))).await;
    watch.assert_socketless();
    let out2: DeployOutput = second.ok();
    let doc = assert_sbom(&second, &out2.image_id, None);
    assert!(second.log().iter().any(|l| l.contains("(syft 1.51.0, ")), "{:?}", second.log());
    assert!(doc["packages"].as_array().unwrap().iter().any(|p| p["name"] == "nginx"), "the image's own packages");
    assert_ne!(out2.container_id, out1.container_id);
    assert!(second.log().iter().any(|l| l == "Draining the previous container for 1s"), "{:?}", second.log());
    let s = status(app).await;
    assert_eq!(s.containers.len(), 1, "{s:?}");
    assert_eq!(s.containers[0].id, out2.container_id);
    assert_eq!(
        docker_cli(&["inspect", "-f", "{{.Name}} {{.HostConfig.RestartPolicy.Name}}", &out2.container_id]),
        "/owd-app_e2eimage-e2ea0002 unless-stopped"
    );
    assert_eq!(
        docker_cli(&[
            "inspect",
            "-f",
            "{{index .Config.Labels \"dev.openwaf.deploy.environment\"}}",
            &out2.container_id
        ]),
        "e2e-env"
    );

    // A deployment whose health check fails leaves the previous container serving, never stopped.
    let failed =
        run(deploy(app, "dep_E2EA0003", Source::Local { image: out1.image.clone() }, 80, 28081, Some("/missing")))
            .await;
    assert!(failed.err().contains("health check failed"), "{}", failed.err());
    assert!(failed.log().iter().any(|l| l.contains("HTTP 404")));
    assert!(failed.log().iter().any(|l| l == "The previous container keeps serving"));
    let s = status(app).await;
    assert_eq!(s.containers.len(), 1, "{s:?}");
    assert_eq!((s.containers[0].id.as_str(), s.containers[0].state.as_str()), (out2.container_id.as_str(), "running"));
    assert_eq!(http("http://127.0.0.1:28081/").await.unwrap().0, 200);

    // A container that exits during start-up fails the deployment at once with its exit code.
    let mut crash = deploy(app, "dep_E2EA0004", Source::Local { image: out1.image.clone() }, 80, 28081, Some("/"));
    if let Op::DeployApp(d) = &mut crash {
        d.run.command = Some(vec!["sh".into(), "-c".into(), "echo boom >&2; exit 3".into()]);
    }
    let crashed = run(crash).await;
    assert!(crashed.err().contains("exited with code 3"), "{}", crashed.err());
    assert!(crashed.lines(Some(LogStream::Stderr)).contains(&"boom".to_string()));
    assert_eq!(http("http://127.0.0.1:28081/").await.unwrap().0, 200);

    // Logs: the tail, with Docker's timestamps.
    http("http://127.0.0.1:28081/?e2e-marker").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let logs = run(Op::AppLogs { resource: app.into(), tail: 5, follow: false, since: None, service: None }).await;
    let n: serde_json::Value = logs.ok();
    let lines = logs.log();
    assert!(n["lines"].as_u64().unwrap() <= 5 && !lines.is_empty());
    assert!(lines.iter().any(|l| l.contains("GET /?e2e-marker")), "{lines:?}");
    assert!(lines.iter().all(|l| l.as_bytes().get(4) == Some(&b'-') && l.contains('Z')), "{lines:?}");

    // Following logs ends only when cancelled, with the "cancelled" error, after streaming new lines.
    let cancel = CancellationToken::new();
    let follow = tokio::spawn(exec(
        Op::AppLogs { resource: app.into(), tail: 0, follow: true, since: None, service: None },
        cancel.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(500)).await;
    http("http://127.0.0.1:28081/?while-following").await.unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    cancel.cancel();
    let followed = tokio::time::timeout(Duration::from_secs(5), follow).await.expect("follow stops on cancel").unwrap();
    assert_eq!(followed.err(), "cancelled");
    assert!(followed.log().iter().any(|l| l.contains("while-following")), "{:?}", followed.log());

    // Stop, start, restart.
    let s: AppState = run(Op::AppAction { resource: app.into(), action: AppActionKind::Stop }).await.ok();
    assert_eq!(s.containers[0].state, "exited");
    let s: AppState = run(Op::AppAction { resource: app.into(), action: AppActionKind::Start }).await.ok();
    assert_eq!(s.containers[0].state, "running");
    let s: AppState = run(Op::AppAction { resource: app.into(), action: AppActionKind::Restart }).await.ok();
    assert_eq!(s.containers[0].state, "running");

    // Remove takes the containers, the routes and the application's tags, not the pulled image's own tag.
    let s: AppState = run(Op::AppAction { resource: app.into(), action: AppActionKind::Remove }).await.ok();
    assert!(s.containers.is_empty());
    assert_eq!(docker_cli(&["images", "-q", "owd/app_e2eimage"]), "");
    assert_ne!(docker_cli(&["images", "-q", "nginx:1.29-alpine"]), "");
    assert!(http("http://127.0.0.1:28081/").await.is_err(), "the router no longer listens for the application");
}

/// The acceptance bar of rolling updates: redeployments under a continuous request loop drop nothing.
#[tokio::test]
async fn rolling_redeploys_drop_no_request() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let app = "app_e2eroll";
    remove_app(app).await;
    let first = run(deploy(app, "dep_E2ER0001", image("nginx:1.29-alpine"), 80, 28083, Some("/"))).await;
    let out: DeployOutput = first.ok();
    let stop = Arc::new(AtomicBool::new(false));
    let (ok, failed) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let mut loops = Vec::new();
    // Four clients, two with keep-alive connections (as the edge has) and two with a new connection per request.
    for i in 0..4 {
        let (stop, ok, failed) = (stop.clone(), ok.clone(), failed.clone());
        loops.push(tokio::spawn(async move {
            let mut b = reqwest::Client::builder().timeout(Duration::from_secs(5));
            if i % 2 == 1 {
                b = b.pool_max_idle_per_host(0);
            }
            let c = b.build().unwrap();
            let mut errors = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                match c.get(on_host("http://127.0.0.1:28083/")).send().await {
                    Ok(r) if r.status() == 200 => {
                        let _ = r.bytes().await;
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(r) => {
                        failed.fetch_add(1, Ordering::Relaxed);
                        errors.push(format!("HTTP {}", r.status()));
                    }
                    Err(e) => {
                        failed.fetch_add(1, Ordering::Relaxed);
                        errors.push(e.to_string());
                    }
                }
            }
            errors
        }));
    }
    let mut image = out.image.clone();
    for n in 2..=4 {
        let dep = format!("dep_E2ER000{n}");
        // Alternately with and without a health check: both switch through the router.
        let health = (n % 2 == 0).then_some("/");
        let r = run(deploy(app, &dep, Source::Local { image: image.clone() }, 80, 28083, health)).await;
        image = r.ok::<DeployOutput>().image;
    }
    stop.store(true, Ordering::Relaxed);
    let mut errors = Vec::new();
    for l in loops {
        errors.extend(l.await.unwrap());
    }
    let (ok, failed) = (ok.load(Ordering::Relaxed), failed.load(Ordering::Relaxed));
    eprintln!("rolling redeploys: {ok} requests answered, {failed} failed");
    assert!(ok > 500, "the loop ran: {ok}");
    assert_eq!(failed, 0, "{errors:?}");
    let s = status(app).await;
    assert_eq!(s.containers.len(), 1);
    assert_eq!(s.containers[0].deployment.as_deref(), Some("dep_E2ER0004"));
    remove_app(app).await;
}

/// An application last deployed by a phase-2 agent (its container publishes the port itself) moves behind the
/// router on its next deployment.
#[tokio::test]
async fn phase2_container_moves_behind_the_router() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let app = "app_e2emig";
    remove_app(app).await;
    run(Op::RouterSync(RouterConfig::default())).await.ok::<RouterState>();
    docker_cli(&["network", "create", NETWORK]);
    docker_ok(&[
        "run",
        "-d",
        "--name",
        "owd-app_e2emig-e2em0001",
        "--label",
        "dev.openwaf.deploy.resource=app_e2emig",
        "--label",
        "dev.openwaf.deploy.deployment=dep_E2EM0001",
        "--network",
        NETWORK,
        "-p",
        "28086:80",
        "nginx:1.29-alpine",
    ]);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(http("http://127.0.0.1:28086/").await.unwrap().0, 200);
    // A route sync before the move leaves the application where it is.
    let sync = RouterConfig {
        preview_port: None,
        resources: vec![ResourceRoutes {
            resource: app.into(),
            routes: vec![Route { listen: Some(28086), hosts: vec![], service: None, port: 80, tls: false }],
        }],
        ..Default::default()
    };
    let st: RouterState = run(Op::RouterSync(sync.clone())).await.ok();
    assert_eq!(st.pending, [app]);
    assert_eq!(http("http://127.0.0.1:28086/").await.unwrap().0, 200);
    let r = run(deploy(app, "dep_E2EM0002", image("nginx:1.29-alpine"), 80, 28086, Some("/"))).await;
    let out: DeployOutput = r.ok();
    assert!(r.log().iter().any(|l| l.starts_with("Moving the application behind the router")), "{:?}", r.log());
    assert_eq!(http("http://127.0.0.1:28086/").await.unwrap().0, 200);
    let s = status(app).await;
    assert_eq!(s.containers.len(), 1);
    assert_eq!(s.containers[0].id, out.container_id);
    let st: RouterState = run(Op::RouterSync(sync)).await.ok();
    assert_eq!((st.active, st.listeners), (vec![app.to_string()], vec![28086]));
    remove_app(app).await;
}

fn crccheck(resource: &str, deployment: &str) -> Op {
    let mut op = deploy(
        resource,
        deployment,
        git("https://github.com/crccheck/docker-hello-world", "master"),
        8000,
        28082,
        Some("/"),
    );
    if let Op::DeployApp(d) = &mut op {
        d.build = Some(build(BuildPack::Dockerfile));
    }
    op
}

fn leftovers() -> (String, usize) {
    let helpers = docker_cli(&["ps", "-aq", "--filter", "label=dev.openwaf.deploy.helper"]);
    let temp = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("owdeploy-"))
        .count();
    // Image archives staged for a load go with it.
    let staged = std::fs::read_dir(crate::oci::staging_root()).map_or(0, |d| d.count());
    (helpers, temp + staged)
}

/// Builder `name` runs the pinned rootless image as an unprivileged user, on the build network, without privileges
/// beyond its user namespace helpers and without any host path: its state and its socket are volumes.
fn assert_rootless_builder(name: &str) {
    let format = "{{.Config.Image}}|{{.Config.User}}|{{.State.Running}}|{{.HostConfig.Privileged}}|\
        {{.HostConfig.NetworkMode}}|{{json .HostConfig.Binds}}|\
        {{json .HostConfig.CapDrop}}{{json .HostConfig.CapAdd}}";
    assert_eq!(
        docker_cli(&["inspect", "-f", format, name]),
        format!(
            "{}|1000:1000|true|false|owd-build-internal|null|[\"ALL\"][\"SETUID\",\"SETGID\"]",
            crate::builder::BUILDKIT_IMAGE
        )
    );
    let mounts = docker_cli(&["inspect", "-f", "{{range .Mounts}}{{.Type}}:{{.Name}} {{end}}", name]);
    let mut mounts: Vec<&str> = mounts.split_whitespace().collect();
    mounts.sort_unstable();
    assert_eq!(mounts, [format!("volume:{name}-sock"), format!("volume:{name}-state")]);
    // Its network has no way out but the build egress proxy, which runs unprivileged on both networks.
    assert_eq!(docker_cli(&["network", "inspect", "-f", "{{.Internal}}", crate::builder::BUILD_NETWORK]), "true");
    let format = "{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|\
        {{json .HostConfig.SecurityOpt}}|{{json .HostConfig.Binds}}|{{len .Mounts}}|{{.State.Running}}";
    assert_eq!(
        docker_cli(&["inspect", "-f", format, crate::egress::CONTAINER]),
        "65534:65534|true|[\"ALL\"]|[\"no-new-privileges\"]|null|0|true"
    );
    let networks = docker_cli(&[
        "inspect",
        "-f",
        "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}",
        crate::egress::CONTAINER,
    ]);
    assert_eq!(networks, "owd-build-egress owd-build-internal");
}

/// Watches the helper containers of the agent while a deployment runs (every 100 ms): how many it saw, and the
/// mounts of any that reached the Engine's socket or a path of the server.
struct HelperWatch {
    stop: Arc<AtomicBool>,
    task: std::thread::JoinHandle<(BTreeSet<String>, Vec<String>)>,
}

impl HelperWatch {
    fn start() -> HelperWatch {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let task = std::thread::spawn(move || {
            let (mut seen, mut bad) = (BTreeSet::new(), Vec::new());
            while !flag.load(Ordering::Relaxed) {
                let ids = docker_cli(&["ps", "-q", "--no-trunc", "--filter", "label=dev.openwaf.deploy.helper"]);
                for id in ids.lines().filter(|l| !l.is_empty()) {
                    let format = "{{range .Mounts}}{{.Type}}:{{.Source}} {{end}}|{{json .HostConfig.Binds}}";
                    let mounts = docker_cli(&["inspect", "-f", format, id]);
                    if mounts.is_empty() {
                        continue; // Already removed.
                    }
                    seen.insert(id.to_string());
                    if mounts.contains("docker.sock") || mounts.contains("bind:") || !mounts.ends_with("|null") {
                        bad.push(format!("{id}: {mounts}"));
                    }
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            (seen, bad)
        });
        HelperWatch { stop, task }
    }

    /// Stops watching; asserts helpers were seen and none had the Engine's socket or a host path.
    fn assert_socketless(self) {
        self.stop.store(true, Ordering::Relaxed);
        let (seen, bad) = self.task.join().unwrap();
        assert!(!seen.is_empty(), "no helper container seen while the deployment ran");
        assert!(bad.is_empty(), "helpers with the Engine's socket or a host path: {bad:?}");
    }
}

/// The SBOMs a command sent: (image digest, service, SPDX document), parts put back together in order.
fn sboms(r: &Run) -> Vec<(String, Option<String>, serde_json::Value)> {
    use base64::Engine;
    use std::io::Read;
    let mut out = Vec::new();
    let mut data = String::new();
    let mut expected = 0;
    for e in &r.events {
        if let Event::Sbom { image_digest, service, part, last, data: d } = e {
            assert_eq!(*part, expected, "parts in order");
            data.push_str(d);
            expected += 1;
            if *last {
                let gz = base64::engine::general_purpose::STANDARD.decode(std::mem::take(&mut data)).unwrap();
                let mut doc = Vec::new();
                flate2::read::GzDecoder::new(gz.as_slice()).read_to_end(&mut doc).unwrap();
                out.push((image_digest.clone(), service.clone(), serde_json::from_slice(&doc).unwrap()));
                expected = 0;
            }
        }
    }
    assert_eq!(expected, 0, "an SBOM without its last part");
    out
}

/// The one SBOM sent for `image_id`, an SPDX 2.3 document with packages.
fn assert_sbom(r: &Run, image_id: &str, service: Option<&str>) -> serde_json::Value {
    let all = sboms(r);
    let found: Vec<_> = all.iter().filter(|(d, s, _)| d == image_id && s.as_deref() == service).collect();
    assert_eq!(
        found.len(),
        1,
        "SBOMs of {image_id} ({service:?}) among {:?}; log: {:?}",
        all.iter().map(|x| (&x.0, &x.1)).collect::<Vec<_>>(),
        r.log()
    );
    let doc = found[0].2.clone();
    assert!(doc["spdxVersion"].as_str().unwrap().starts_with("SPDX-2."), "{doc}");
    assert!(!doc["packages"].as_array().unwrap().is_empty(), "{doc}");
    doc
}

#[tokio::test]
async fn git_deploy_builds_the_commit_and_cancel_cleans_up() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let app = "app_e2egit";
    remove_app(app).await;
    let watch = HelperWatch::start();
    let r = run(crccheck(app, "dep_E2EG0001")).await;
    watch.assert_socketless();
    let out: DeployOutput = r.ok();
    // The built image's SBOM, from BuildKit's attestation, for the image the deployment runs.
    assert_sbom(&r, &out.image_id, None);
    assert!(
        r.log().iter().any(|l| l.starts_with("Checked and loaded owd/app_e2egit:dep_e2eg0001 (sha256:")),
        "{:?}",
        r.log()
    );
    assert_eq!(
        r.steps(),
        [Step::Fetching, Step::Building, Step::Starting, Step::HealthCheck, Step::Switching, Step::Cleaning]
    );
    let commit = out.commit.clone().expect("commit");
    assert_eq!(commit.len(), 40);
    assert!(r.log().iter().any(|l| l == &format!("Checked out commit {commit}")));
    assert!(r.log().iter().any(|l| l == "Building on the rootless BuildKit builder owd-buildkit"), "{:?}", r.log());
    assert!(r.log().iter().any(|l| l.contains("load build definition from Dockerfile")), "build output streamed");
    assert_rootless_builder("owd-buildkit");
    let (code, body) = http("http://127.0.0.1:28082/").await.unwrap();
    assert_eq!(code, 200);
    assert!(body.contains("Hello World"), "{body}");
    let labels = docker_cli(&["image", "inspect", "-f", "{{json .Config.Labels}}", &out.image]);
    assert!(labels.contains("\"dev.openwaf.deploy.resource\":\"app_e2egit\""), "{labels}");
    assert!(labels.contains("\"dev.openwaf.deploy.deployment\":\"dep_E2EG0001\""), "{labels}");
    assert_eq!(leftovers(), (String::new(), 0));

    // A pinned commit is fetched as such.
    let mut pinned = crccheck(app, "dep_E2EG0002");
    if let Op::DeployApp(d) = &mut pinned
        && let Source::Git { reference, .. } = &mut d.source
    {
        *reference = commit.clone();
    }
    let out2: DeployOutput = run(pinned).await.ok();
    assert_eq!(out2.commit.as_deref(), Some(commit.as_str()));

    // Cancel in the middle of a slow build (npm install): no helper, no temporary directory, no image, and the
    // running deployment is untouched.
    let slow =
        deploy(app, "dep_E2EG0003", git("https://github.com/docker/welcome-to-docker", "main"), 3000, 28082, Some("/"));
    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::channel(1024);
    let (ev, batcher) = Events::start("cancel".into(), tx);
    let token = cancel.clone();
    let task = tokio::spawn(async move {
        let o = crate::execute(slow, &ev, &token).await;
        drop(ev);
        batcher.await.unwrap();
        o
    });
    let mut saw_building = false;
    while let Some(Outgoing::Event(e)) = rx.recv().await {
        if let Event::Log { lines, .. } = &e.event
            && saw_building
            && lines.iter().any(|l| l.contains("RUN npm ci"))
        {
            // The slow step started: cancel while it runs.
            tokio::time::sleep(Duration::from_secs(2)).await;
            cancel.cancel();
            break;
        }
        saw_building |= matches!(e.event, Event::Step { step: Step::Building, .. });
    }
    assert!(saw_building);
    let o = tokio::time::timeout(Duration::from_secs(30), task).await.expect("cancel is prompt").unwrap();
    assert_eq!(o, Outcome::Error { message: "cancelled".into() });
    assert_eq!(leftovers(), (String::new(), 0));
    assert_eq!(docker_cli(&["images", "-q", "owd/app_e2egit:dep_e2eg0003"]), "");
    // The build session closes with the helper: BuildKit stops the step it was running.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let building = docker_cli(&["top", "owd-buildkit", "-eo", "args"]);
    assert!(!building.contains("npm ci"), "{building}");
    let s = status(app).await;
    assert_eq!(s.containers.len(), 1);
    assert_eq!(s.containers[0].id, out2.container_id);
    assert_eq!(http("http://127.0.0.1:28082/").await.unwrap().0, 200);
    remove_app(app).await;
}

#[tokio::test]
async fn railpack_builds_a_node_app() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let app = "app_e2erailpack";
    remove_app(app).await;
    let mut d = app_spec_git(app, "dep_E2EP0001", "https://github.com/render-examples/express-hello-world", "main");
    d.build = Some(BuildSpec {
        args: [("NODE_ENV".to_string(), "production".to_string())].into(),
        ..build(BuildPack::Railpack)
    });
    d.run.port = 3000;
    d.run.publish = Some(28084);
    let watch = HelperWatch::start();
    let r = run(Op::DeployApp(d.clone())).await;
    watch.assert_socketless();
    let out: DeployOutput = r.ok();
    assert_sbom(&r, &out.image_id, None);
    // Without a policy (an older control plane): open, through the build egress proxy (npm, mise, apt there).
    assert_eq!(egress_report(&r).0, EgressMode::Open);
    assert!(r.log().iter().any(|l| l.starts_with("Build egress (open): ")), "{:?}", r.log());
    assert_eq!(
        r.steps(),
        [Step::Fetching, Step::Building, Step::Starting, Step::HealthCheck, Step::Switching, Step::Cleaning]
    );
    assert!(
        r.log().iter().any(|l| l == "Building with Railpack 0.43.0 on the rootless BuildKit builder owd-buildkit"),
        "{:?}",
        r.log()
    );
    assert!(r.log().iter().any(|l| l.contains("railpack")), "Railpack's own output is streamed");
    let (code, body) = http("http://127.0.0.1:28084/").await.unwrap();
    assert_eq!(code, 200);
    assert!(body.contains("Hello from Render"), "{body}");
    let labels = docker_cli(&["image", "inspect", "-f", "{{json .Config.Labels}}", &out.image]);
    assert!(labels.contains("\"dev.openwaf.deploy.resource\":\"app_e2erailpack\""), "{labels}");
    assert_eq!(docker_cli(&["images", "-q", &format!("{}-railpack", out.image)]), "", "the unlabelled image goes");
    // The plan ran on the rootless builder, which stays for the next builds.
    assert_rootless_builder("owd-buildkit");
    assert_eq!(leftovers(), (String::new(), 0));
    // A second build reuses the builder (and its cache).
    d.deployment = "dep_E2EP0002".into();
    d.run.image_tag = "owd/app_e2erailpack:dep_e2ep0002".into();
    let again = run(Op::DeployApp(d)).await;
    again.ok::<DeployOutput>();
    assert!(!again.log().iter().any(|l| l.starts_with("Creating the rootless BuildKit builder")), "{:?}", again.log());
    assert!(http("http://127.0.0.1:28084/").await.unwrap().1.contains("Hello from Render"));
    remove_app(app).await;
}

fn app_spec_git(resource: &str, deployment: &str, url: &str, reference: &str) -> AppDeploy {
    app_deploy(resource, deployment, git(url, reference), 80, None, Some("/"))
}

/// A Git server over SSH (sshd with one authorized deploy key) on the default bridge, where helpers run, with
/// repositories for the tests: a mirror of a public repository and two static sites.
struct GitServer {
    ip: String,
    key: String,
    host_key: String,
}

const GIT_SERVER: &str = "owd-e2e-gitssh";

fn git_server() -> GitServer {
    docker_cli(&["rm", "-f", GIT_SERVER]);
    let dir = crate::git::TempDir::new().unwrap();
    let key = dir.path().join("key");
    let o = Proc::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let dockerfile = "FROM alpine:3.22\n\
        RUN apk add --no-cache openssh-server git nodejs && ssh-keygen -A \
          && adduser -D -s /bin/sh git && sed -i 's/^git:!/git:*/' /etc/shadow \
          && mkdir -p /home/git/.ssh /srv/git && chown -R git:git /home/git /srv/git\n\
        CMD [\"/bin/sh\", \"-c\", \"echo \\\"$AUTH_KEY\\\" > /home/git/.ssh/authorized_keys && chown git /home/git/.ssh/authorized_keys && chmod 600 /home/git/.ssh/authorized_keys && exec /usr/sbin/sshd -D -e\"]\n";
    std::fs::write(dir.path().join("Dockerfile"), dockerfile).unwrap();
    docker_ok(&["build", "-q", "-t", "owd-e2e-gitssh", dir.path().to_str().unwrap()]);
    docker_ok(&["run", "-d", "--name", GIT_SERVER, "-e", &format!("AUTH_KEY={}", public.trim()), "owd-e2e-gitssh"]);
    let script = r#"set -e
git config --global user.email e2e@example.com
git config --global user.name e2e
git config --global init.defaultBranch main
git clone -q --bare https://github.com/crccheck/docker-hello-world /srv/git/hello.git
mkdir /tmp/site && cd /tmp/site && git init -q
printf '%s' '{"name":"site","version":"1.0.0","private":true,"scripts":{"build":"node build.js"}}' > package.json
printf '%s' "require('fs').mkdirSync('dist',{recursive:true});require('fs').writeFileSync('dist/index.html','<h1>built by railpack</h1>')" > build.js
git add -A && git commit -qm site && git clone -q --bare . /srv/git/site.git
mkdir /tmp/plain && cd /tmp/plain && git init -q && mkdir public
echo '<h1>plain static</h1>' > public/index.html && echo secret > notes.txt
git add -A && git commit -qm plain && git clone -q --bare . /srv/git/plain.git
mkdir /tmp/probe && cd /tmp/probe && git init -q
printf 'FROM busybox:1.37\nARG GREETING\nRUN mkdir /www && cat /proc/self/uid_map > /www/uid_map && echo "$GREETING" > /www/greeting\nCMD ["httpd", "-f", "-p", "8080", "-h", "/www"]\n' > Dockerfile
printf '[submodule "sub"]\n\tpath = sub\n\turl = https://127.0.0.1:1/nothing.git\n' > .gitmodules
git add -A && git update-index --add --cacheinfo 160000,0123456789abcdef0123456789abcdef01234567,sub
git commit -qm probe && git clone -q --bare . /srv/git/probe.git
mkdir /tmp/egress && cd /tmp/egress && git init -q
cat > Dockerfile <<'EOF'
FROM curlimages/curl:8.17.0 AS probe
ARG URLS
USER root
RUN mkdir /out && for u in $URLS; do curl -fsS --max-time 20 -o /dev/null "$u" || exit 1; done
RUN rc=0; curl -sS --noproxy '*' --max-time 10 -o /dev/null http://192.0.2.1/ || rc=$?; echo "$rc" > /out/direct
RUN if nslookup example.org >/dev/null 2>&1; then echo resolved; else echo refused; fi > /out/dns
FROM busybox:1.37
COPY --from=probe /out /www
CMD ["httpd", "-f", "-p", "8080", "-h", "/www"]
EOF
git add -A && git commit -qm egress && git clone -q --bare . /srv/git/egress.git
"#;
    docker_ok(&["exec", "-u", "git", GIT_SERVER, "sh", "-c", script]);
    let ip = docker_cli(&["inspect", "-f", "{{.NetworkSettings.IPAddress}}", GIT_SERVER]);
    let pubkey = docker_cli(&["exec", GIT_SERVER, "cat", "/etc/ssh/ssh_host_ed25519_key.pub"]);
    let mut f = pubkey.split(' ');
    let host_key = format!("{ip} {} {}", f.next().unwrap(), f.next().unwrap());
    GitServer { ip, key: std::fs::read_to_string(&key).unwrap(), host_key }
}

#[tokio::test]
async fn deploy_keys_clone_over_ssh_and_static_sites_build() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let srv = git_server();
    let ssh = |known: Vec<String>| SshAuth { private_key: srv.key.clone(), known_hosts: known };
    let source = |repo: &str, known: Vec<String>| Source::Git {
        url: format!("ssh://git@{}:22/srv/git/{repo}", srv.ip),
        reference: "main".into(),
        auth: None,
        ssh: Some(ssh(known)),
        commit: None,
    };

    // Deploy key, unknown host: trusted on first use, and reported.
    let app = "app_e2essh";
    remove_app(app).await;
    let mut d = app_deploy(app, "dep_E2ES0001", source("hello.git", vec![]), 8000, Some(28085), Some("/"));
    if let Source::Git { reference, .. } = &mut d.source {
        *reference = "master".into();
    }
    d.build = Some(build(BuildPack::Dockerfile));
    let r = run(Op::DeployApp(d.clone())).await;
    let out: DeployOutput = r.ok();
    assert_eq!(out.known_hosts, std::slice::from_ref(&srv.host_key), "{:?}", r.log());
    assert!(!r.log().iter().any(|l| l.contains("PRIVATE KEY")), "the key never reaches the log");
    assert!(http("http://127.0.0.1:28085/").await.unwrap().1.contains("Hello World"));
    // Pinned: the learnt key is accepted, another one refused.
    d.deployment = "dep_E2ES0002".into();
    d.run.image_tag = "owd/app_e2essh:dep_e2es0002".into();
    if let Source::Git { ssh: Some(k), .. } = &mut d.source {
        k.known_hosts = out.known_hosts.clone();
    }
    let pinned: DeployOutput = run(Op::DeployApp(d.clone())).await.ok();
    assert!(pinned.known_hosts.is_empty());
    d.deployment = "dep_E2ES0003".into();
    if let Source::Git { ssh: Some(k), .. } = &mut d.source {
        k.known_hosts = vec![format!(
            "{} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
            srv.ip
        )];
    }
    let refused = run(Op::DeployApp(d)).await;
    assert!(refused.err().contains("git fetch failed"), "{}", refused.err());
    assert!(refused.log().iter().any(|l| l.contains("Host key verification failed")), "{:?}", refused.log());
    assert_eq!(status(app).await.containers[0].id, pinned.container_id);
    remove_app(app).await;

    // Static site built by Railpack (npm run build), served from dist as a single-page application.
    let site = "app_e2estatic";
    remove_app(site).await;
    let mut d =
        app_deploy(site, "dep_E2ET0001", source("site.git", vec![srv.host_key.clone()]), 8080, Some(28088), Some("/"));
    d.build = Some(BuildSpec {
        build_command: Some("npm run build".into()),
        publish_dir: Some("dist".into()),
        spa: true,
        ..build(BuildPack::Static)
    });
    let r = run(Op::DeployApp(d)).await;
    let out: DeployOutput = r.ok();
    assert_sbom(&r, &out.image_id, None);
    assert!(r.log().iter().any(|l| l == "Packaging the static site from dist"), "{:?}", r.log());
    let (code, body) = http("http://127.0.0.1:28088/").await.unwrap();
    assert_eq!((code, body.trim()), (200, "<h1>built by railpack</h1>"));
    assert_eq!(http("http://127.0.0.1:28088/some/route").await.unwrap().1.trim(), "<h1>built by railpack</h1>");
    assert_eq!(docker_cli(&["images", "-q", &format!("{}-build", out.image)]), "", "the build image is removed");
    // Plain static files of a directory, without a build: unknown paths are 404, files outside it are not served.
    let mut d =
        app_deploy(site, "dep_E2ET0002", source("plain.git", vec![srv.host_key.clone()]), 8080, Some(28088), Some("/"));
    d.build = Some(BuildSpec { publish_dir: Some("public".into()), ..build(BuildPack::Static) });
    run(Op::DeployApp(d)).await.ok::<DeployOutput>();
    assert_eq!(http("http://127.0.0.1:28088/").await.unwrap().1.trim(), "<h1>plain static</h1>");
    assert_eq!(http("http://127.0.0.1:28088/notes.txt").await.unwrap().0, 404);
    assert_eq!(leftovers(), (String::new(), 0));
    remove_app(site).await;
    docker_cli(&["rm", "-f", GIT_SERVER]);
}

#[tokio::test]
async fn untrusted_builds_are_rootless_pinned_and_skip_submodules() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let srv = git_server();
    let head =
        docker_cli(&["exec", "-u", "git", GIT_SERVER, "git", "--git-dir=/srv/git/probe.git", "rev-parse", "main"]);
    let app = "app_e2efork";
    remove_app(app).await;
    let spec = |deployment: &str, commit: Option<&str>, untrusted: bool| {
        let source = Source::Git {
            url: format!("ssh://git@{}:22/srv/git/probe.git", srv.ip),
            reference: "main".into(),
            auth: None,
            ssh: Some(SshAuth { private_key: srv.key.clone(), known_hosts: vec![srv.host_key.clone()] }),
            commit: commit.map(str::to_string),
        };
        let mut d = app_deploy(app, deployment, source, 8080, Some(28091), Some("/greeting"));
        d.build = Some(BuildSpec {
            args: [("GREETING".to_string(), "from-build-arg".to_string())].into(),
            untrusted,
            ..build(BuildPack::Dockerfile)
        });
        Op::DeployApp(d)
    };
    // The application's own code gets its submodules: this one names a repository that does not exist.
    let own = run(spec("dep_E2EF0001", None, false)).await;
    assert!(own.err().contains("git fetch failed"), "{}", own.err());
    assert!(own.log().iter().any(|l| l.contains("nothing.git")), "{:?}", own.log());
    // Untrusted code: never its submodules, and only the commit it was approved at.
    let moved = run(spec("dep_E2EF0002", Some("0123456789abcdef0123456789abcdef01234567"), true)).await;
    assert!(moved.err().contains("git fetch failed"), "{}", moved.err());
    assert!(moved.log().iter().any(|l| l.contains("not at the commit to deploy")), "{:?}", moved.log());
    assert_eq!(docker_cli(&["images", "-q", "owd/app_e2efork:dep_e2ef0002"]), "");
    let r = run(spec("dep_E2EF0003", Some(&head), true)).await;
    let out: DeployOutput = r.ok();
    assert_eq!(out.commit.as_deref(), Some(head.as_str()));
    assert!(!r.log().iter().any(|l| l.contains("nothing.git")), "{:?}", r.log());
    assert!(
        r.log().iter().any(|l| l == "Building on the rootless BuildKit builder owd-buildkit-untrusted"),
        "{:?}",
        r.log()
    );
    // Its own builder and cache, nothing shared with the application's builds.
    assert_rootless_builder("owd-buildkit-untrusted");
    // The build step was root of a user namespace only: its root is an unprivileged id on the host.
    let (_, map) = http("http://127.0.0.1:28091/uid_map").await.unwrap();
    let first: Vec<&str> = map.split_whitespace().take(2).collect();
    assert!(first[0] == "0" && first[1] != "0", "{map}");
    assert_eq!(http("http://127.0.0.1:28091/greeting").await.unwrap().1.trim(), "from-build-arg");
    assert_eq!(leftovers(), (String::new(), 0));
    remove_app(app).await;
    docker_cli(&["rm", "-f", GIT_SERVER]);
}

/// An `Event::Egress` entry as the tests compare it: (host, port, decision, reason).
type Entry = (String, u16, EgressDecision, Option<String>);

/// The `Event::Egress` a build sent: (mode, enforced, entries).
fn egress_report(r: &Run) -> (EgressMode, bool, Vec<Entry>) {
    let reports: Vec<_> = r
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Egress { mode, enforced, entries, .. } => Some((
                *mode,
                *enforced,
                entries.iter().map(|x| (x.host.clone(), x.port, x.decision, x.reason.clone())).collect(),
            )),
            _ => None,
        })
        .collect();
    assert_eq!(reports.len(), 1, "one egress report per build: {:?}", r.log());
    reports.into_iter().next().unwrap()
}

/// Build steps reach the Internet through the build egress proxy only: an allowlist lets its destinations through
/// and fails the build on any other (reported as it happens and at the end), audit records every destination, open
/// refuses private addresses; whatever the policy, a direct connection and an outside name lookup fail.
#[tokio::test]
async fn build_egress_policies_are_enforced_by_the_proxy() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let srv = git_server();
    let app = "app_e2eegress";
    remove_app(app).await;
    let spec = |deployment: &str, urls: &str, egress: BuildEgress| {
        let source = Source::Git {
            url: format!("ssh://git@{}:22/srv/git/egress.git", srv.ip),
            reference: "main".into(),
            auth: None,
            ssh: Some(SshAuth { private_key: srv.key.clone(), known_hosts: vec![srv.host_key.clone()] }),
            commit: None,
        };
        let mut d = app_deploy(app, deployment, source, 8080, Some(28095), Some("/direct"));
        d.build = Some(BuildSpec {
            args: [("URLS".to_string(), urls.to_string())].into(),
            no_cache: true,
            egress: Some(egress),
            ..build(BuildPack::Dockerfile)
        });
        Op::DeployApp(d)
    };
    let allowlist = BuildEgress { mode: EgressMode::Allowlist, allow: vec!["example.com".into()] };

    // Allowlist: the allowed host over HTTPS (CONNECT) and plain HTTP.
    let r = run(spec("dep_E2EX0001", "https://example.com/ http://example.com/", allowlist.clone())).await;
    r.ok::<DeployOutput>();
    assert!(
        r.log().iter().any(|l| l == "Build egress: allowlist of 1 destinations, through the build egress proxy only")
    );
    let (mode, enforced, entries) = egress_report(&r);
    assert_eq!((mode, enforced), (EgressMode::Allowlist, true));
    for port in [443, 80] {
        let e = ("example.com".to_string(), port, EgressDecision::Allowed, None);
        assert!(entries.contains(&e), "{entries:?}");
    }
    // The step could neither connect directly (no route: curl's 7) nor resolve an outside name.
    assert_eq!(http("http://127.0.0.1:28095/direct").await.unwrap().1.trim(), "7");
    assert_eq!(http("http://127.0.0.1:28095/dns").await.unwrap().1.trim(), "refused");
    assert!(r.log().iter().any(|l| l.starts_with("Build egress (allowlist): ")), "{:?}", r.log());

    // Allowlist: any other host fails the build, denied as it happens and in the report.
    let r = run(spec("dep_E2EX0002", "https://example.org/", allowlist.clone())).await;
    assert!(r.err().contains("build failed"), "{}", r.err());
    assert!(r.log().iter().any(|l| l == "Build egress denied: example.org:443 (not_allowed)"), "{:?}", r.log());
    let (_, _, entries) = egress_report(&r);
    assert!(entries.contains(&("example.org".into(), 443, EgressDecision::Denied, Some("not_allowed".into()))));
    // An address instead of a name is refused in allowlist mode.
    let r = run(spec("dep_E2EX0003", "https://203.0.113.10/", allowlist)).await;
    assert!(r.err().contains("build failed"), "{}", r.err());
    let literal = ("203.0.113.10".to_string(), 443, EgressDecision::Denied, Some("ip_literal".to_string()));
    assert!(egress_report(&r).2.contains(&literal));

    // Audit: every destination allowed and recorded.
    let audit = BuildEgress { mode: EgressMode::Audit, allow: vec![] };
    let r = run(spec("dep_E2EX0004", "https://example.com/ https://example.org/", audit)).await;
    r.ok::<DeployOutput>();
    let (mode, _, entries) = egress_report(&r);
    assert_eq!(mode, EgressMode::Audit);
    for host in ["example.com", "example.org"] {
        assert!(entries.iter().any(|e| e.0 == host && e.1 == 443 && e.2 == EgressDecision::Allowed), "{entries:?}");
    }

    // Open: private addresses (cloud metadata) are still refused, after resolution too.
    let r = run(spec("dep_E2EX0005", "http://169.254.169.254/", BuildEgress::OPEN)).await;
    assert!(r.err().contains("build failed"), "{}", r.err());
    let (mode, _, entries) = egress_report(&r);
    assert_eq!(mode, EgressMode::Open);
    assert_eq!(entries, [("169.254.169.254".to_string(), 80, EgressDecision::Denied, Some("private_address".into()))]);
    // A public name resolving to loopback (DNS rebinding) is refused once the proxy resolved it.
    let r = run(spec("dep_E2EX0006", "http://localhost.localtest.me/", BuildEgress::OPEN)).await;
    assert!(r.err().contains("build failed"), "{}", r.err());
    let denied = "Build egress denied: localhost.localtest.me:80 (private_address)";
    assert!(r.log().iter().any(|l| l == denied), "{:?}", r.log());
    assert_eq!(leftovers(), (String::new(), 0));
    remove_app(app).await;
    docker_cli(&["rm", "-f", GIT_SERVER]);
}

/// The registry of [`private_registry_pulls_and_builds_with_the_selected_credential_only`]: `registry:2` asking for
/// Basic credentials (htpasswd), alone in a network namespace behind the host, at a public address (a documentation
/// range, which the build egress proxy does not refuse), as an outside registry would be.
const REGISTRY: &str = "203.0.113.50:5000";
const REGISTRY_IP: &str = "203.0.113.50";
const REGISTRY_GW: &str = "203.0.113.49";
const REGISTRY_CONTAINER: &str = "owd-e2e-registry";
const REGISTRY_IMAGE: &str = "registry:2";
/// The host's end of the registry's link (not `owd…`, the prefix of Deploy's bridges).
const REGISTRY_LINK: &str = "ngreg-h";
const REGISTRY_USER: &str = "robot";
const REGISTRY_PASSWORD: &str = "e2e-Registry-Passw0rd";
/// `htpasswd -nbB robot e2e-Registry-Passw0rd`.
const REGISTRY_HTPASSWD: &str = "robot:$2y$05$EpqFh2VURqO1NAHkDAF7feEZqb1L.UhwW.TnV9iO9M3jQUzaSH5ti";
const BUILDKITD_CONFIG: &str = "/etc/buildkit/buildkitd.toml";
/// Appended to the trusted builder's configuration while the test runs: the registry speaks plain HTTP.
const BUILDKITD_REGISTRY: &str = "\n[registry.\"203.0.113.50:5000\"]\n  http = true\n";

/// Runs `docker args` with `input` on its standard input: (success, standard output).
fn docker_stdin(args: &[&str], input: &str) -> (bool, String) {
    use std::io::Write;
    let mut c = Proc::new("docker")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("docker CLI");
    c.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned())
}

/// The private registry, with `base` (busybox with `/base-marker`) pushed to it; removed on drop, with the base
/// image the tests pulled, and the builder's configuration put back.
struct PrivateRegistry {
    base: String,
    builder_config: Option<String>,
}

impl PrivateRegistry {
    fn start(base: &str) -> PrivateRegistry {
        let index = docker_cli(&["info", "-f", "{{json .RegistryConfig.IndexConfigs}}"]);
        assert!(index.contains(&format!("\"{REGISTRY}\"")), "the Engine must list {REGISTRY} as an insecure registry");
        docker_cli(&["rm", "-f", REGISTRY_CONTAINER]);
        sh(&["ip", "link", "del", REGISTRY_LINK]);
        let script = "mkdir -p /auth && printf '%s\\n' \"$HTPASSWD\" > /auth/htpasswd \
            && exec registry serve /etc/docker/registry/config.yml";
        docker_ok(&[
            "run",
            "-d",
            "--name",
            REGISTRY_CONTAINER,
            "--network",
            "none",
            "-e",
            &format!("HTPASSWD={REGISTRY_HTPASSWD}"),
            "-e",
            "REGISTRY_AUTH=htpasswd",
            "-e",
            "REGISTRY_AUTH_HTPASSWD_REALM=e2e",
            "-e",
            "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd",
            "--entrypoint",
            "sh",
            REGISTRY_IMAGE,
            "-c",
            script,
        ]);
        let pid = docker_cli(&["inspect", "-f", "{{.State.Pid}}", REGISTRY_CONTAINER]);
        assert!(sh(&["ip", "link", "add", REGISTRY_LINK, "type", "veth", "peer", "name", "eth1", "netns", &pid]));
        assert!(sh(&["ip", "addr", "add", &format!("{REGISTRY_GW}/30"), "dev", REGISTRY_LINK]));
        assert!(sh(&["ip", "link", "set", REGISTRY_LINK, "up"]));
        for args in [
            vec!["addr", "add", &format!("{REGISTRY_IP}/30"), "dev", "eth1"],
            vec!["link", "set", "eth1", "up"],
            vec!["route", "add", "default", "via", REGISTRY_GW],
        ] {
            assert!(sh(&[&["nsenter", "-t", &pid, "-n", "ip"], args.as_slice()].concat()), "{args:?}");
        }
        let url = format!("http://{REGISTRY}/v2/");
        let ready = (0..40).any(|_| {
            std::thread::sleep(Duration::from_millis(250));
            let args = ["-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "1", &url];
            Proc::new("curl").args(args).output().is_ok_and(|o| o.stdout == b"401")
        });
        assert!(ready, "{url} does not ask for credentials");
        let reg = PrivateRegistry { base: base.to_string(), builder_config: None };
        // A base image of our own, pushed with a throwaway client configuration.
        docker_cli(&["rm", "-f", "owd-e2e-regbase"]);
        docker_ok(&[
            "run",
            "--name",
            "owd-e2e-regbase",
            "busybox:1.37",
            "sh",
            "-c",
            "echo private-base > /base-marker",
        ]);
        docker_ok(&["commit", "owd-e2e-regbase", base]);
        docker_ok(&["rm", "owd-e2e-regbase"]);
        let client = crate::git::TempDir::new().unwrap();
        let config = client.path().to_str().unwrap();
        let login = ["--config", config, "login", "-u", REGISTRY_USER, "--password-stdin", REGISTRY];
        assert!(docker_stdin(&login, REGISTRY_PASSWORD).0, "docker login {REGISTRY}");
        docker_ok(&["--config", config, "push", base]);
        docker_ok(&["rmi", base]);
        reg
    }

    /// The trusted builder reaches the registry over plain HTTP (BuildKit reads its configuration when it starts).
    fn trust_in_builder(&mut self) {
        let name = crate::builder::Builder::Trusted.name();
        let current = docker_cli(&["exec", name, "cat", BUILDKITD_CONFIG]);
        let original = current.replace(BUILDKITD_REGISTRY.trim_end(), "").trim_end().to_string();
        write_builder_config(name, &format!("{original}{BUILDKITD_REGISTRY}"));
        self.builder_config = Some(original);
    }
}

/// Replaces the configuration of builder `name` and restarts it.
fn write_builder_config(name: &str, config: &str) {
    let dir = crate::git::TempDir::new().unwrap();
    let file = dir.path().join("buildkitd.toml");
    std::fs::write(&file, format!("{}\n", config.trim_end())).unwrap();
    docker_ok(&["cp", file.to_str().unwrap(), &format!("{name}:{BUILDKITD_CONFIG}")]);
    docker_ok(&["restart", name]);
}

impl Drop for PrivateRegistry {
    fn drop(&mut self) {
        if let Some(config) = &self.builder_config {
            write_builder_config(crate::builder::Builder::Trusted.name(), config);
        }
        docker_cli(&["rm", "-f", REGISTRY_CONTAINER]);
        docker_cli(&["rmi", &self.base]);
        sh(&["ip", "link", "del", REGISTRY_LINK]);
    }
}

/// What a build helper shows of its Docker configuration: `$HOME/.docker/config.json` (`link <target>`, `file` or
/// `none`), `keyed` when the config on the secrets tmpfs has the registry's entry, and `copy <path>` for each regular
/// file of `$HOME/.docker` holding the password or its base64 pair (both read from stdin).
const CONFIG_PROBE: &str = r#"IFS= read -r p
IFS= read -r b
f="$HOME/.docker/config.json"
if [ -L "$f" ]; then echo "link $(readlink "$f")"; elif [ -e "$f" ]; then echo file; else echo none; fi
grep -qF '"203.0.113.50:5000"' /run/owd/docker-config.json 2>/dev/null && echo keyed
find "$HOME/.docker" -type f -exec grep -lF -e "$p" -e "$b" {} + 2>/dev/null | sed 's/^/copy /'
true
"#;

/// Watches the build helpers while a deployment runs (every 100 ms) with [`CONFIG_PROBE`]: every distinct answer.
struct ConfigWatch {
    stop: Arc<AtomicBool>,
    task: std::thread::JoinHandle<BTreeSet<String>>,
}

impl ConfigWatch {
    fn start(secrets: String) -> ConfigWatch {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let task = std::thread::spawn(move || {
            let mut seen = BTreeSet::new();
            while !flag.load(Ordering::Relaxed) {
                let filter = format!("network={}", crate::builder::BUILD_NETWORK);
                let ids = docker_cli(&["ps", "-q", "--filter", "label=dev.openwaf.deploy.helper", "--filter", &filter]);
                for id in ids.lines().filter(|l| !l.is_empty()) {
                    let (_, out) = docker_stdin(&["exec", "-i", id, "sh", "-c", CONFIG_PROBE], &secrets);
                    seen.extend(out.lines().map(str::to_string));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            seen
        });
        ConfigWatch { stop, task }
    }

    fn stop(self) -> BTreeSet<String> {
        self.stop.store(true, Ordering::Relaxed);
        self.task.join().unwrap()
    }
}

/// Everything a command sent: its events and its outcome.
fn sent(r: &Run) -> String {
    format!("{:?}\n{:?}", r.outcome, r.events)
}

/// Private registries: an image deployment and a Compose project pull with the selected credential, a build `FROM`
/// the registry gets it from its build helper, and each fails with the agent's text without it (or with a wrong
/// one). A second application without the credential cannot use the base image the first one's build left in the
/// builder's cache (`--pull`). The credential never shows in what the agent sends, in the build egress proxy's or
/// BuildKit's logs, or in an image; in the build helper it stays on the secrets tmpfs, which goes with the helper.
#[tokio::test]
async fn private_registry_pulls_and_builds_with_the_selected_credential_only() {
    use base64::Engine;
    if !enabled("OWDEPLOY_TEST_DOCKER") || !enabled("OWDEPLOY_TEST_REGISTRY") {
        return;
    }
    let base = format!("{REGISTRY}/e2e/base:1");
    let mut reg = PrivateRegistry::start(&base);
    let auth =
        RegistryAuth { server: REGISTRY.into(), username: REGISTRY_USER.into(), password: REGISTRY_PASSWORD.into() };
    let wrong = RegistryAuth { password: "not-the-Passw0rd".into(), ..auth.clone() };
    let pair = base64::engine::general_purpose::STANDARD.encode(format!("{REGISTRY_USER}:{REGISTRY_PASSWORD}"));
    let secrets = [REGISTRY_PASSWORD.to_string(), pair.clone(), wrong.password.clone()];
    let assert_secret_free = |what: &str, text: &str| {
        for s in &secrets {
            assert!(!text.contains(s.as_str()), "{what} carries a credential: {text}");
        }
    };
    let anonymous = format!(
        "{REGISTRY} refused the anonymous pull of e2e/base (401): the application selects no credential for {REGISTRY}"
    );
    let rejected = format!(
        "{REGISTRY} rejected the selected credential (401): the username or token is wrong or expired; update it in \
         the organization's registry credentials"
    );
    let mut runs = Vec::new();

    // The builder reaches the registry over plain HTTP (made by a first build when missing: it cannot pull yet).
    let srv = git_server();
    let repo = format!(
        "set -e\nrm -rf /tmp/private /srv/git/private.git && mkdir /tmp/private && cd /tmp/private && git init -q\n\
         printf 'FROM {base}\\nRUN mkdir /www && cp /base-marker /www/index.html\\nCMD [\"httpd\", \"-f\", \"-p\", \
         \"8080\", \"-h\", \"/www\"]\\n' > Dockerfile\n\
         git add -A && git commit -qm private && git clone -q --bare . /srv/git/private.git\n"
    );
    docker_ok(&["exec", "-u", "git", GIT_SERVER, "sh", "-c", &repo]);
    let build_op = |app: &str, deployment: &str, publish: u16, registry_auth: Vec<RegistryAuth>| {
        let source = Source::Git {
            url: format!("ssh://git@{}:22/srv/git/private.git", srv.ip),
            reference: "main".into(),
            auth: None,
            ssh: Some(SshAuth { private_key: srv.key.clone(), known_hosts: vec![srv.host_key.clone()] }),
            commit: None,
        };
        let mut d = app_deploy(app, deployment, source, 8080, Some(publish), Some("/"));
        d.build = Some(BuildSpec { registry_auth, ..build(BuildPack::Dockerfile) });
        Op::DeployApp(d)
    };
    let (first, second) = ("app_e2eregbuild", "app_e2eregbuild2");
    remove_app(first).await;
    remove_app(second).await;
    let builder = crate::builder::Builder::Trusted.name();
    if docker_cli(&["ps", "-aq", "--filter", &format!("name=^{builder}$")]).is_empty() {
        runs.push(run(build_op(second, "dep_E2ER0010", 28098, vec![])).await);
    }
    reg.trust_in_builder();

    // An image deployment: refused without the credential and with a wrong one, pulled with it.
    let image_app = "app_e2eregimage";
    remove_app(image_app).await;
    let image_op = |deployment: &str, auth: Option<RegistryAuth>| {
        let source = Source::Image { image: base.clone(), auth };
        let mut d = app_deploy(image_app, deployment, source, 8080, Some(28096), Some("/"));
        d.run.command = busybox_site("private-image");
        Op::DeployApp(d)
    };
    let r = run(image_op("dep_E2ER0001", None)).await;
    assert_eq!(r.err(), anonymous, "{:?}", r.log());
    runs.push(r);
    let r = run(image_op("dep_E2ER0002", Some(wrong.clone()))).await;
    assert_eq!(r.err(), rejected, "{:?}", r.log());
    runs.push(r);
    let r = run(image_op("dep_E2ER0003", Some(auth.clone()))).await;
    r.ok::<DeployOutput>();
    assert_eq!(http("http://127.0.0.1:28096/").await.unwrap().1.trim(), "private-image");
    runs.push(r);
    remove_app(image_app).await;

    // A Compose project: a service pulled from the registry (every time), another built from it.
    let compose_app = "app_e2eregcompose";
    remove_app(compose_app).await;
    let compose = format!(
        "services:\n  web:\n    image: {base}\n    pull_policy: always\n    command: [\"sh\", \"-c\", \"mkdir -p /www \
         && cp /base-marker /www/index.html && exec httpd -f -p 8080 -h /www\"]\n  api:\n    build:\n      context: .\n      \
         dockerfile_inline: |\n        FROM {base}\n        RUN cp /base-marker /built-marker\n    command: [\"sleep\", \
         \"3600\"]\n"
    );
    let compose_op = |deployment: &str, registry_auth: Vec<RegistryAuth>| {
        Op::DeployCompose(ComposeDeploy {
            resource: compose_app.into(),
            deployment: deployment.into(),
            network: NETWORK.into(),
            source: ComposeSource::Inline { content: compose.clone() },
            env: Default::default(),
            volumes: vec![],
            files: vec![],
            labels: [(LABEL_ENVIRONMENT.to_string(), "e2e-env".to_string())].into(),
            routes: vec![Route {
                listen: Some(28100),
                hosts: vec![],
                service: Some("web".into()),
                port: 8080,
                tls: false,
            }],
            no_cache: false,
            egress: None,
            registry_auth,
        })
    };
    let r = run(compose_op("dep_E2ER0004", vec![])).await;
    let err = r.err();
    assert!(err == anonymous || r.log().contains(&anonymous), "{err}: {:?}", r.log());
    runs.push(r);
    let r = run(compose_op("dep_E2ER0005", vec![auth.clone()])).await;
    r.ok::<ComposeOutput>();
    assert!(r.log().iter().any(|l| l == &format!("registry credentials for: {REGISTRY}")), "{:?}", r.log());
    assert_eq!(http("http://127.0.0.1:28100/").await.unwrap().1.trim(), "private-base");
    runs.push(r);
    remove_app(compose_app).await;

    // A build FROM the registry: without the credential and with a wrong one it fails at FROM, with the agent's
    // text after BuildKit's; with it, it builds and runs.
    let r = run(build_op(first, "dep_E2ER0011", 28097, vec![])).await;
    assert!(r.err().contains("build failed"), "{}", r.err());
    assert!(r.log().contains(&anonymous), "{:?}", r.log());
    runs.push(r);
    let r = run(build_op(first, "dep_E2ER0012", 28097, vec![wrong.clone()])).await;
    assert!(r.err().contains("build failed"), "{}", r.err());
    assert!(r.log().contains(&rejected), "{:?}", r.log());
    runs.push(r);
    let watch = ConfigWatch::start(format!("{REGISTRY_PASSWORD}\n{pair}\n"));
    let r = run(build_op(first, "dep_E2ER0013", 28097, vec![auth.clone()])).await;
    let seen = watch.stop();
    let out: DeployOutput = r.ok();
    assert_eq!(http("http://127.0.0.1:28097/").await.unwrap().1.trim(), "private-base");
    runs.push(r);
    // The helper's Docker config stayed a link to the secrets tmpfs, with the registry's entry, and no file of
    // `~/.docker` (buildx's state) ever held the credential.
    assert!(seen.contains("link /run/owd/docker-config.json") && seen.contains("keyed"), "{seen:?}");
    assert!(!seen.iter().any(|l| l == "file" || l.starts_with("copy ")), "{seen:?}");

    // A second application without the credential, after the first one's build cached the base image: BuildKit
    // resolves it at the registry again and is refused.
    let r = run(build_op(second, "dep_E2ER0014", 28098, vec![])).await;
    assert!(r.err().contains("build failed"), "{}", r.err());
    assert!(r.log().contains(&anonymous), "{:?}", r.log());
    assert_eq!(docker_cli(&["images", "-q", "owd/app_e2eregbuild2:dep_e2er0014"]), "");
    runs.push(r);

    // Nowhere else: what the agent sent, the proxy's and BuildKit's logs, the built image.
    for (i, r) in runs.iter().enumerate() {
        assert_secret_free(&format!("command {i}"), &sent(r));
    }
    for c in [crate::egress::CONTAINER, builder] {
        let o = Proc::new("docker").args(["logs", c]).output().unwrap();
        let logs = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert_secret_free(&format!("the logs of {c}"), &logs);
    }
    assert_secret_free("the built image", &docker_cli(&["image", "inspect", &out.image]));
    assert_secret_free("the built image's history", &docker_cli(&["history", "--no-trunc", &out.image]));
    // The helpers, their secrets tmpfs with them, are gone.
    assert_eq!(leftovers(), (String::new(), 0));
    remove_app(first).await;
    remove_app(second).await;
    docker_cli(&["rm", "-f", GIT_SERVER]);
    drop(reg);
}

const COMPOSE: &str = r#"
services:
  web:
    image: nginx:1.29-alpine
    ports: ["28089:80"]
    depends_on: [api]
  api:
    build:
      context: .
      dockerfile_inline: |
        FROM busybox:1.37
        RUN cat /proc/self/uid_map > /uid_map
    command: ["sh", "-c", "mkdir -p /www && echo api-$${GREETING} > /www/index.html && exec httpd -f -p 5678 -h /www"]
    environment:
      GREETING: from-file
"#;

const NGINX_CONF: &str = "server {\n  listen 80;\n  location /api/ { proxy_pass http://api:5678/; }\n  location / { return 200 'web-ok'; }\n}\n";

#[tokio::test]
async fn compose_app_routes_one_of_two_services() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let app = "app_e2ecompose";
    remove_app(app).await;
    run(Op::VolumeRemove { resource: app.into(), names: None }).await.ok::<serde_json::Value>();
    let spec = |dep: &str| ComposeDeploy {
        resource: app.into(),
        deployment: dep.into(),
        network: NETWORK.into(),
        source: ComposeSource::Inline { content: COMPOSE.into() },
        env: [("GREETING".to_string(), "from-app".to_string())].into(),
        volumes: vec![VolumeMount { name: "data".into(), path: "/data".into(), service: Some("api".into()) }],
        files: vec![FileMount {
            path: "/etc/nginx/conf.d/default.conf".into(),
            content: NGINX_CONF.into(),
            service: Some("web".into()),
        }],
        labels: [(LABEL_ENVIRONMENT.to_string(), "e2e-env".to_string())].into(),
        routes: vec![Route {
            listen: Some(28087),
            hosts: vec!["shop.e2e.test".into()],
            service: Some("web".into()),
            port: 80,
            tls: false,
        }],
        no_cache: false,
        egress: None,
        registry_auth: Vec::new(),
    };
    let watch = HelperWatch::start();
    let r = run(Op::DeployCompose(spec("dep_E2EC0001"))).await;
    watch.assert_socketless();
    let out: ComposeOutput = r.ok();
    assert_eq!(egress_report(&r).0, EgressMode::Open, "Compose builds go through the build egress proxy too");
    // An SBOM for each service's image: built (api), pulled (web).
    for s in &out.services {
        let id = docker_cli(&["inspect", "-f", "{{.Image}}", &s.container_id]);
        assert_sbom(&r, &id, Some(s.service.as_str()));
    }
    // Containers, networks and volumes carry Compose's labels (logs per service, removal, earlier agents).
    let web = out.services.iter().find(|s| s.service == "web").unwrap();
    assert_eq!(
        docker_cli(&[
            "inspect",
            "-f",
            "{{.Name}} {{index .Config.Labels \"com.docker.compose.project\"}} {{index .Config.Labels \"com.docker.compose.service\"}} {{.HostConfig.RestartPolicy.Name}}",
            &web.container_id
        ]),
        "/owd-app_e2ecompose-web-1 owd-app_e2ecompose web unless-stopped"
    );
    assert_eq!(
        docker_cli(&[
            "network",
            "ls",
            "--format",
            "{{.Name}}",
            "--filter",
            "label=com.docker.compose.project=owd-app_e2ecompose"
        ]),
        "owd-app_e2ecompose_default"
    );
    assert_eq!(out.project, "owd-app_e2ecompose");
    let services: Vec<(&str, &str)> = out.services.iter().map(|s| (s.service.as_str(), s.state.as_str())).collect();
    assert_eq!(services, [("api", "running"), ("web", "running")]);
    assert_eq!(r.steps(), [Step::Fetching, Step::Building, Step::Starting, Step::Switching, Step::Cleaning]);
    // The api service was built on the rootless builder: root of its build step was not the host's.
    assert!(r.log().iter().any(|l| l == "Building on the rootless BuildKit builder owd-buildkit"), "{:?}", r.log());
    let e: ExecOutput = run(Op::Exec(ExecSpec {
        resource: app.into(),
        service: Some("api".into()),
        command: vec!["cat".into(), "/uid_map".into()],
        timeout_secs: 10,
    }))
    .await
    .ok();
    let first: Vec<&str> = e.output.split_whitespace().take(2).collect();
    assert!(first[0] == "0" && first[1] != "0", "{}", e.output);
    let base = "http://127.0.0.1:28087";
    assert_eq!(http_host(&format!("{base}/"), Some("shop.e2e.test")).await.unwrap(), (200, "web-ok".into()));
    // The routed service reaches the other one on the project network; the application's variables win.
    let (code, body) = http_host(&format!("{base}/api/"), Some("Shop.E2E.test")).await.unwrap();
    assert_eq!((code, body.trim()), (200, "api-from-app"));
    assert_eq!(http_host(&format!("{base}/"), Some("other.test")).await.unwrap().0, 404);
    // Host ports of the file are not published.
    assert!(http("http://127.0.0.1:28089/").await.is_err());
    // Exec in a service, and the volume mounted there.
    let e: ExecOutput = run(Op::Exec(ExecSpec {
        resource: app.into(),
        service: Some("api".into()),
        command: vec!["sh".into(), "-c".into(), "echo kept > /data/f && printenv GREETING".into()],
        timeout_secs: 10,
    }))
    .await
    .ok();
    assert_eq!((e.exit_code, e.output.trim()), (Some(0), "from-app"));
    // Redeploy: the services are recreated, the volume stays.
    // The pulled image's SBOM comes from the agent's cache the second time.
    let again = run(Op::DeployCompose(spec("dep_E2EC0002"))).await;
    again.ok::<ComposeOutput>();
    assert!(again.log().iter().any(|l| l.contains("(already generated)")), "{:?}", again.log());
    let e: ExecOutput = run(Op::Exec(ExecSpec {
        resource: app.into(),
        service: Some("api".into()),
        command: vec!["cat".into(), "/data/f".into()],
        timeout_secs: 10,
    }))
    .await
    .ok();
    assert_eq!(e.output.trim(), "kept");
    let logs =
        run(Op::AppLogs { resource: app.into(), tail: 50, follow: false, since: None, service: Some("web".into()) })
            .await;
    logs.ok::<serde_json::Value>();
    remove_app(app).await;
    assert_eq!(
        docker_cli(&["network", "ls", "-q", "--filter", "label=com.docker.compose.project=owd-app_e2ecompose"]),
        ""
    );
    let v: serde_json::Value = run(Op::VolumeRemove { resource: app.into(), names: None }).await.ok();
    assert_eq!(v["removed"], serde_json::json!(["owd-app_e2ecompose-data"]));
}

/// A Compose application deployed by an earlier agent (Compose itself, run in a helper with the Engine's socket, on
/// the project the agent adapted) is updated in place by this one (same container name, same project network), and
/// stays manageable: logs per service, stop and start, removal.
#[tokio::test]
async fn compose_apps_of_earlier_agents_are_updated_in_place() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let app = "app_e2ecompat";
    let project = "owd-app_e2ecompat";
    remove_app(app).await;
    let d = crate::docker::client().unwrap();
    crate::deploy::ensure_network(&d, NETWORK, Some("e2e-env")).await.unwrap();
    let site = |text: &str| format!("mkdir -p /www && echo {text} > /www/index.html && exec httpd -f -p 8080 -h /www");
    let earlier = serde_json::json!({
        "name": project,
        "services": {"web": {
            "image": "busybox:1.37",
            "command": ["sh", "-c", site("earlier")],
            "labels": {"dev.openwaf.deploy.resource": app, "dev.openwaf.deploy.deployment": "dep_E2EO0001"},
            "restart": "unless-stopped",
            "networks": {"default": null, "owd_environment": {"aliases": ["owd-app_e2ecompat-web"]}},
        }},
        "networks": {
            "default": {"name": "owd-app_e2ecompat_default", "driver": "bridge", "enable_ipv6": false,
                        "driver_opts": {crate::firewall::BRIDGE_OPTION: crate::firewall::bridge_name("owd-app_e2ecompat_default")}},
            "owd_environment": {"name": NETWORK, "external": true},
        },
    });
    let mut compose = Proc::new("docker")
        .args(["run", "--rm", "-i", "-v", "/var/run/docker.sock:/var/run/docker.sock", "docker:29.9.3-cli"])
        .args(["compose", "-p", project, "-f", "-", "up", "-d", "--wait"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    compose.stdin.take().unwrap().write_all(earlier.to_string().as_bytes()).unwrap();
    let o = compose.wait_with_output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let earlier_id = docker_cli(&["inspect", "-f", "{{.Id}}", "owd-app_e2ecompat-web-1"]);
    let network = docker_cli(&["network", "inspect", "-f", "{{.Id}}", "owd-app_e2ecompat_default"]);
    let s = status(app).await;
    assert_eq!(s.containers.len(), 1, "{s:?}");
    assert_eq!(s.containers[0].deployment.as_deref(), Some("dep_E2EO0001"));

    let content =
        format!("services:\n  web:\n    image: busybox:1.37\n    command: [\"sh\", \"-c\", \"{}\"]\n", site("current"));
    let spec = ComposeDeploy {
        resource: app.into(),
        deployment: "dep_E2EO0002".into(),
        network: NETWORK.into(),
        source: ComposeSource::Inline { content },
        env: Default::default(),
        volumes: vec![],
        files: vec![],
        labels: [(LABEL_ENVIRONMENT.to_string(), "e2e-env".to_string())].into(),
        routes: vec![Route { listen: Some(28094), hosts: vec![], service: Some("web".into()), port: 8080, tls: false }],
        no_cache: false,
        egress: None,
        registry_auth: Vec::new(),
    };
    let r = run(Op::DeployCompose(spec)).await;
    let out: ComposeOutput = r.ok();
    assert_eq!(out.services.len(), 1, "{:?}", out.services);
    let web = &out.services[0];
    assert_ne!(web.container_id, earlier_id, "recreated");
    assert_eq!(docker_cli(&["inspect", "-f", "{{.Name}}", &web.container_id]), "/owd-app_e2ecompat-web-1");
    assert_eq!(docker_cli(&["network", "inspect", "-f", "{{.Id}}", "owd-app_e2ecompat_default"]), network);
    assert_eq!(http("http://127.0.0.1:28094/").await.unwrap().1.trim(), "current");
    let s = status(app).await;
    assert_eq!(s.containers.len(), 1, "{s:?}");
    assert_eq!(s.containers[0].deployment.as_deref(), Some("dep_E2EO0002"));
    run(Op::AppLogs { resource: app.into(), tail: 10, follow: false, since: None, service: Some("web".into()) })
        .await
        .ok::<serde_json::Value>();
    let s: AppState = run(Op::AppAction { resource: app.into(), action: AppActionKind::Stop }).await.ok();
    assert_eq!(s.containers[0].state, "exited");
    let s: AppState = run(Op::AppAction { resource: app.into(), action: AppActionKind::Start }).await.ok();
    assert_eq!(s.containers[0].state, "running");
    let s: AppState = run(Op::AppAction { resource: app.into(), action: AppActionKind::Remove }).await.ok();
    assert!(s.containers.is_empty());
    assert_eq!(
        docker_cli(&["network", "ls", "-q", "--filter", &format!("label=com.docker.compose.project={project}")]),
        ""
    );
}

#[tokio::test]
async fn volumes_survive_redeploys_and_exec_reports_exit_codes() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let app = "app_e2evol";
    remove_app(app).await;
    run(Op::VolumeRemove { resource: app.into(), names: None }).await.ok::<serde_json::Value>();
    let spec = |dep: &str, text: &str| {
        let mut d = app_spec(app, dep, 8080, Some(28090 + 1));
        d.run.command = busybox_site("vol");
        d.run.volumes = vec![VolumeMount { name: "data".into(), path: "/data".into(), service: None }];
        d.run.files = vec![FileMount { path: "/etc/app/config.txt".into(), content: text.into(), service: None }];
        d
    };
    run(Op::DeployApp(spec("dep_E2EV0001", "first config"))).await.ok::<DeployOutput>();
    let ex = |cmd: &str, timeout_secs: u32| {
        Op::Exec(ExecSpec {
            resource: app.into(),
            service: None,
            command: vec!["sh".into(), "-c".into(), cmd.into()],
            timeout_secs,
        })
    };
    let e: ExecOutput = run(ex("echo persisted > /data/state && cat /etc/app/config.txt", 10)).await.ok();
    assert_eq!((e.exit_code, e.output.trim(), e.timed_out), (Some(0), "first config", false));
    // A file mount is read-only.
    let e: ExecOutput = run(ex("echo x > /etc/app/config.txt", 10)).await.ok();
    assert_ne!(e.exit_code, Some(0));

    run(Op::DeployApp(spec("dep_E2EV0002", "second config\n"))).await.ok::<DeployOutput>();
    let r = run(ex("cat /data/state /etc/app/config.txt; echo to-stderr >&2; exit 7", 10)).await;
    let e: ExecOutput = r.ok();
    assert_eq!(e.exit_code, Some(7));
    // Standard output and error are separate streams: their relative order is not kept.
    let mut lines: Vec<&str> = e.output.lines().collect();
    lines.sort_unstable();
    assert_eq!(lines, ["persisted", "second config", "to-stderr"]);
    assert!(r.lines(Some(LogStream::Stderr)).contains(&"to-stderr".to_string()), "output is streamed");
    // Only the current deployment's files are kept.
    let files = std::path::Path::new(&std::env::var("OWDEPLOY_AGENT_STATE").unwrap()).join("files/app_e2evol");
    let dirs: Vec<String> =
        std::fs::read_dir(&files).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(dirs, ["dep_e2ev0002"]);

    // A command past its timeout is killed and reported as such.
    let started = std::time::Instant::now();
    let e: ExecOutput = run(ex("echo before; sleep 60", 2)).await.ok();
    assert!(e.timed_out && e.output.contains("before"), "{e:?}");
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());

    // Volumes outlive the application's containers until removed explicitly (refused while containers exist).
    assert!(run(Op::VolumeRemove { resource: app.into(), names: None }).await.err().contains("still has containers"));
    remove_app(app).await;
    assert_eq!(docker_cli(&["volume", "ls", "-q", "--filter", "name=owd-app_e2evol-data"]), "owd-app_e2evol-data");
    let v: serde_json::Value = run(Op::VolumeRemove { resource: app.into(), names: None }).await.ok();
    assert_eq!(v["removed"], serde_json::json!(["owd-app_e2evol-data"]));
    assert!(!files.exists());
}

fn app_spec(resource: &str, deployment: &str, port: u16, publish: Option<u16>) -> AppDeploy {
    let mut d = app_deploy(resource, deployment, image("busybox:1.37"), port, publish, Some("/"));
    // The image source is retagged per deployment; busybox has no web server of its own running.
    d.run.command = busybox_site(resource);
    d
}

#[tokio::test]
async fn preview_listener_routes_by_host() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let prs = ["app_e2eprev-pr1", "app_e2eprev-pr2"];
    for p in prs {
        remove_app(p).await;
    }
    let routes = |n: usize| {
        let hosts = vec![format!("pr-{n}.preview.e2e.test")];
        vec![Route { listen: None, hosts, service: None, port: 8080, tls: false }]
    };
    let sync = RouterConfig {
        preview_port: Some(28099),
        resources: prs
            .iter()
            .enumerate()
            .map(|(i, p)| ResourceRoutes { resource: p.to_string(), routes: routes(i + 1) })
            .collect(),
        ..Default::default()
    };
    let st: RouterState = run(Op::RouterSync(sync.clone())).await.ok();
    assert_eq!(st.pending.len(), 2, "not deployed yet");
    for (i, p) in prs.iter().enumerate() {
        let mut d = app_spec(p, &format!("dep_E2EW000{}", i + 1), 8080, None);
        d.run.command = busybox_site(&format!("preview-{}", i + 1));
        d.routes = Some(routes(i + 1));
        run(Op::DeployApp(d)).await.ok::<DeployOutput>();
    }
    let st: RouterState = run(Op::RouterSync(sync)).await.ok();
    assert_eq!(st.active.len(), 2);
    assert!(st.listeners.contains(&28099));
    let url = "http://127.0.0.1:28099/";
    assert_eq!(http_host(url, Some("pr-1.preview.e2e.test")).await.unwrap().1.trim(), "preview-1");
    assert_eq!(http_host(url, Some("pr-2.preview.e2e.test")).await.unwrap().1.trim(), "preview-2");
    assert_eq!(http_host(url, Some("pr-3.preview.e2e.test")).await.unwrap().0, 404);
    // Closing a preview: its container and route go, the other stays.
    remove_app(prs[0]).await;
    assert_eq!(http_host(url, Some("pr-1.preview.e2e.test")).await.unwrap().0, 404);
    assert_eq!(http_host(url, Some("pr-2.preview.e2e.test")).await.unwrap().1.trim(), "preview-2");
    remove_app(prs[1]).await;
    run(Op::RouterSync(RouterConfig::default())).await.ok::<RouterState>();
}

#[tokio::test]
async fn prune_keeps_listed_and_used_images() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let app = "app_e2eprune";
    remove_app(app).await;
    for img in ["busybox:1.37", "alpine:3.22", "nginx:1.29-alpine", "hello-world:latest"] {
        let o = Proc::new("docker").args(["pull", "-q", img]).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    for (src, tag) in [
        ("busybox:1.37", "dep_1"),
        ("alpine:3.22", "dep_2"),
        ("nginx:1.29-alpine", "dep_3"),
        ("hello-world:latest", "dep_4"),
    ] {
        docker_cli(&["tag", src, &format!("owd/{app}:{tag}")]);
    }
    // An image a container still uses stays even when not kept.
    docker_cli(&["create", "--name", "owd-e2e-prune-user", &format!("owd/{app}:dep_4")]);
    let r = run(Op::ImagePrune { resource: app.into(), keep: vec![format!("owd/{app}:dep_3")] }).await;
    let v: serde_json::Value = r.ok();
    assert_eq!(v["removed"], serde_json::json!([format!("owd/{app}:dep_1"), format!("owd/{app}:dep_2")]));
    let left = docker_cli(&["images", "--format", "{{.Repository}}:{{.Tag}}", &format!("owd/{app}")]);
    let mut left: Vec<&str> = left.lines().collect();
    left.sort();
    assert_eq!(left, [format!("owd/{app}:dep_3"), format!("owd/{app}:dep_4")]);
    // The pulled images keep their own tags.
    assert_ne!(docker_cli(&["images", "-q", "busybox:1.37"]), "");
    docker_cli(&["rm", "-f", "owd-e2e-prune-user"]);
    remove_app(app).await;
    assert_eq!(docker_cli(&["images", "-q", &format!("owd/{app}")]), "");
}

fn sh(cmd: &[&str]) -> bool {
    Proc::new(cmd[0]).args(&cmd[1..]).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

/// A network namespace standing for an outside client at `ip`, behind the host address `gw`.
fn client_ns(name: &str, ip: &str, gw: &str) {
    let host_if = format!("{name}-h");
    sh(&["ip", "netns", "del", name]);
    sh(&["ip", "link", "del", &host_if]);
    assert!(sh(&["ip", "netns", "add", name]));
    assert!(sh(&["ip", "link", "add", &host_if, "type", "veth", "peer", "name", "eth0", "netns", name]));
    assert!(sh(&["ip", "addr", "add", &format!("{gw}/24"), "dev", &host_if]));
    assert!(sh(&["ip", "link", "set", &host_if, "up"]));
    assert!(sh(&["ip", "-n", name, "addr", "add", &format!("{ip}/24"), "dev", "eth0"]));
    assert!(sh(&["ip", "-n", name, "link", "set", "eth0", "up"]));
    assert!(sh(&["ip", "-n", name, "route", "add", "default", "via", gw]));
}

fn curl_from(ns: &str, url: &str) -> bool {
    sh(&["ip", "netns", "exec", ns, "curl", "-sf", "-o", "/dev/null", "--max-time", "3", url])
}

fn iptables(args: &[&str]) -> String {
    tables("iptables", args)
}

fn tables(bin: &str, args: &[&str]) -> String {
    let o = Proc::new(bin).args(args).output().unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn rules(allow: &str, ports: &[u16], deny: &[&str]) -> FirewallRules {
    FirewallRules {
        allow: vec![allow.into()],
        ports: ports.to_vec(),
        deny: deny.iter().map(|d| d.to_string()).collect(),
    }
}

/// Removes every rule and chain of the agent, in both families, and its saved rules.
fn reset_firewall() {
    for bin in ["iptables", "ip6tables"] {
        while sh(&[bin, "-D", "DOCKER-USER", "-j", "OWDEPLOY"]) {}
        while sh(&[bin, "-D", "INPUT", "-j", "OWDEPLOY-IN"]) {}
        let chains = ["OWDEPLOY", "OWDEPLOY-SRC", "OWDEPLOY-EGRESS", "OWDEPLOY-IN", "OWDEPLOY-HOST"];
        for chain in chains {
            sh(&[bin, "-F", chain]);
        }
        for chain in chains {
            sh(&[bin, "-X", chain]);
        }
    }
    let nat_jumps: [&[&str]; 2] = [
        &["PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "OWDEPLOY-NAT"],
        &["OUTPUT", "!", "-d", "127.0.0.0/8", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "OWDEPLOY-NAT"],
    ];
    for j in nat_jumps {
        while sh(&[&["iptables", "-t", "nat", "-D"], j].concat()) {}
    }
    sh(&["iptables", "-t", "nat", "-F", "OWDEPLOY-NAT"]);
    sh(&["iptables", "-t", "nat", "-X", "OWDEPLOY-NAT"]);
    let state = std::path::PathBuf::from(std::env::var("OWDEPLOY_AGENT_STATE").unwrap());
    let _ = std::fs::remove_file(state.join("firewall.json"));
}

/// Router listeners are published ports: the firewall keeps them reachable from the edge only.
#[tokio::test]
async fn firewall_allows_only_listed_sources() {
    if !enabled("OWDEPLOY_TEST_DOCKER") || !enabled("OWDEPLOY_TEST_FIREWALL") {
        return;
    }
    let app = "app_e2efw";
    remove_app(app).await;
    run(deploy(app, "dep_E2EF0001", image("nginx:1.29-alpine"), 80, 28090, Some("/"))).await.ok::<DeployOutput>();
    client_ns("ngfa", "10.231.0.2", "10.231.0.1");
    client_ns("ngfb", "10.232.0.2", "10.232.0.1");
    // Without rules both clients reach the listener.
    assert!(curl_from("ngfa", "http://10.231.0.1:28090/"));
    assert!(curl_from("ngfb", "http://10.232.0.1:28090/"));

    let rules = rules("10.231.0.0/24", &[28090], &[]);
    let r = run(Op::FirewallSync(rules.clone())).await;
    let v: serde_json::Value = r.ok();
    eprintln!("firewall sync: {v}");
    assert!(curl_from("ngfa", "http://10.231.0.1:28090/"), "allowed source blocked");
    assert!(!curl_from("ngfb", "http://10.232.0.1:28090/"), "other source not blocked");
    // Syncing again replaces the rules: still one jump, same chain.
    run(Op::FirewallSync(rules)).await.ok::<serde_json::Value>();
    let user = iptables(&["-S", "DOCKER-USER"]);
    assert_eq!(user.matches("-j OWDEPLOY").count(), 1, "{user}");
    eprintln!(
        "DOCKER-USER:\n{user}OWDEPLOY:\n{}OWDEPLOY-SRC:\n{}",
        iptables(&["-S", "OWDEPLOY"]),
        iptables(&["-S", "OWDEPLOY-SRC"])
    );
    // A redeployment (through the router) keeps the port guarded.
    run(deploy(app, "dep_E2EF0002", image("nginx:1.29-alpine"), 80, 28090, Some("/"))).await.ok::<DeployOutput>();
    assert!(curl_from("ngfa", "http://10.231.0.1:28090/"));
    assert!(!curl_from("ngfb", "http://10.232.0.1:28090/"));
    // Saved for the next start of the agent, which applies it again.
    let state = std::path::PathBuf::from(std::env::var("OWDEPLOY_AGENT_STATE").unwrap());
    assert!(state.join("firewall.json").exists());
    assert_eq!(crate::firewall::reconcile().await.unwrap(), Vec::<String>::new(), "in place: nothing repaired");

    // `csf -r` flushes every chain: the next check repairs them, and a check after that finds nothing to do.
    sh(&["iptables", "-D", "DOCKER-USER", "-j", "OWDEPLOY"]);
    for (table, chain) in [("filter", "OWDEPLOY"), ("filter", "OWDEPLOY-SRC"), ("nat", "OWDEPLOY-NAT")] {
        sh(&["iptables", "-t", table, "-F", chain]);
    }
    assert!(!curl_from("ngfa", "http://10.231.0.1:28090/"), "flushed: the listener is not routed");
    let repaired = crate::firewall::reconcile().await.unwrap();
    assert!(repaired.iter().any(|r| r.contains("DOCKER-USER")), "{repaired:?}");
    assert_eq!(crate::firewall::reconcile().await.unwrap(), Vec::<String>::new());
    assert!(curl_from("ngfa", "http://10.231.0.1:28090/"));
    assert!(!curl_from("ngfb", "http://10.232.0.1:28090/"));

    // A second application adds a listener without recreating the router: the first one never stops answering.
    let router_id = || docker_cli(&["inspect", "-f", "{{.Id}}", crate::router::CONTAINER]);
    let before = router_id();
    let stop = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicU64::new(0));
    let prober = {
        let (stop, failed) = (stop.clone(), failed.clone());
        tokio::task::spawn_blocking(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                if !curl_from("ngfa", "http://10.231.0.1:28090/") {
                    failed.fetch_add(1, Ordering::Relaxed);
                }
                n += 1;
            }
            n
        })
    };
    let app2 = "app_e2efw2";
    remove_app(app2).await;
    run(deploy(app2, "dep_E2EF0003", image("nginx:1.29-alpine"), 80, 28091, Some("/"))).await.ok::<DeployOutput>();
    run(Op::FirewallSync(self::rules("10.231.0.0/24", &[28090, 28091], &[]))).await.ok::<serde_json::Value>();
    stop.store(true, Ordering::Relaxed);
    let probes = prober.await.unwrap();
    assert_eq!(router_id(), before, "the router was recreated for a new port");
    assert_eq!(failed.load(Ordering::Relaxed), 0, "requests failed while a port was added ({probes} probes)");
    assert!(curl_from("ngfa", "http://10.231.0.1:28091/"));
    assert!(!curl_from("ngfb", "http://10.232.0.1:28091/"));

    // A port the control plane no longer lists stays guarded while the router listens on it.
    run(Op::FirewallSync(self::rules("10.231.0.0/24", &[], &[]))).await.ok::<serde_json::Value>();
    assert!(!curl_from("ngfb", "http://10.232.0.1:28090/"));
    assert!(curl_from("ngfa", "http://10.231.0.1:28090/"));

    // Clean up everything the test created.
    remove_app(app2).await;
    remove_app(app).await;
    reset_firewall();
    for ns in ["ngfa", "ngfb"] {
        sh(&["ip", "netns", "del", ns]);
    }
}

/// A network namespace standing for a server-side service at `ip` (on the link of the host address `gw`, no other
/// route: replies to masqueraded containers stay on the link, and the server's reverse lookup of its own address
/// fails at once instead of delaying its start), answering HTTP on port 80. Returns the server process once it
/// answers the host.
fn service_ns(name: &str, ip: &str, gw: &str) -> std::process::Child {
    client_ns(name, ip, gw);
    assert!(sh(&["ip", "-n", name, "route", "del", "default"]));
    let child = Proc::new("ip")
        .args(["netns", "exec", name, "python3", "-m", "http.server", "80", "--bind", ip])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let url = format!("http://{ip}/");
    let ready = (0..40).any(|_| {
        std::thread::sleep(Duration::from_millis(250));
        sh(&["curl", "-sf", "-o", "/dev/null", "--max-time", "1", &url])
    });
    assert!(ready, "{url} does not answer the host");
    child
}

/// Whether `url` answers from inside the application's container (Exec, busybox wget).
async fn wget_in(app: &str, url: &str) -> bool {
    let cmd = format!("wget -q -O /dev/null -T 3 {url}");
    let spec = ExecSpec {
        resource: app.into(),
        service: None,
        command: vec!["sh".into(), "-c".into(), cmd],
        timeout_secs: 10,
    };
    let out = run(Op::Exec(spec)).await.ok::<ExecOutput>();
    eprintln!("{app} → {url}: exit {:?} {}", out.exit_code, out.output.trim());
    out.exit_code == Some(0)
}

/// The egress guard: containers on Deploy networks (one the agent creates, with an `owd…` bridge, and one created
/// before, with Docker's `br-…`) reach the Internet, their router and DNS, not cloud metadata, private addresses,
/// the server itself or the control plane's denied hosts; IPv6 gets the same rules, and both families are repaired.
/// Commands only act on the application's own containers.
#[tokio::test]
async fn firewall_guards_container_egress() {
    if !enabled("OWDEPLOY_TEST_DOCKER") || !enabled("OWDEPLOY_TEST_FIREWALL") {
        return;
    }
    reset_firewall();
    let (app, legacy) = ("app_e2eguard", "app_e2eguardold");
    remove_app(app).await;
    remove_app(legacy).await;
    let new_net = "owd-e2eguard0001";
    let old_net = "owd-e2eguardold1";
    let drop_network = |n: &str| {
        sh(&["docker", "network", "disconnect", "-f", n, crate::router::CONTAINER]);
        sh(&["docker", "network", "rm", n]);
    };
    drop_network(new_net);
    drop_network(old_net);
    docker_ok(&["network", "create", old_net]);
    let mut d = app_deploy(app, "dep_E2EG0001", image("nginx:1.29-alpine"), 80, Some(28092), Some("/"));
    d.network = new_net.into();
    run(Op::DeployApp(d)).await.ok::<DeployOutput>();
    let mut d = app_deploy(legacy, "dep_E2EG0002", image("nginx:1.29-alpine"), 80, Some(28093), Some("/"));
    d.network = old_net.into();
    run(Op::DeployApp(d)).await.ok::<DeployOutput>();
    let bridge =
        docker_cli(&["network", "inspect", "-f", "{{index .Options \"com.docker.network.bridge.name\"}}", new_net]);
    assert_eq!(bridge, crate::firewall::bridge_name(new_net), "the agent names its networks' bridges");
    assert_eq!(docker_cli(&["network", "inspect", "-f", "{{.EnableIPv6}}", new_net]), "false");

    // Server-side services: cloud metadata, a private host, a control-plane host, and one on the server itself.
    // (Interfaces named `owd…` are Deploy's bridges: the test's own stay clear of that prefix.)
    let mut servers = vec![
        service_ns("ngmeta", "169.254.169.254", "169.254.169.1"),
        service_ns("ngpriv", "10.233.0.2", "10.233.0.1"),
        service_ns("ngcp", "198.51.100.7", "198.51.100.1"),
    ];
    let gateway = docker_cli(&["network", "inspect", "-f", "{{(index .IPAM.Config 0).Gateway}}", new_net]);
    servers.push(
        Proc::new("python3")
            .args(["-m", "http.server", "28199", "--bind", "0.0.0.0"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let local = format!("http://{gateway}:28199/");
    let up = (0..40).any(|_| {
        std::thread::sleep(Duration::from_millis(250));
        sh(&["curl", "-sf", "-o", "/dev/null", "--max-time", "1", &local])
    });
    assert!(up, "the server's own service does not answer");
    let metadata = "http://169.254.169.254/";
    let private = "http://10.233.0.2/";
    let control = "http://198.51.100.7/";
    let host = format!("http://{gateway}:28199/");

    // Without the agent's jumps (as on a server before this agent), everything is reachable.
    sh(&["iptables", "-D", "DOCKER-USER", "-j", "OWDEPLOY"]);
    sh(&["iptables", "-D", "INPUT", "-j", "OWDEPLOY-IN"]);
    for url in [metadata, private, control, host.as_str()] {
        assert!(wget_in(app, url).await, "{url} unreachable before the guard: the test setup is wrong");
    }
    let repaired = crate::firewall::reconcile().await.unwrap();
    assert!(repaired.iter().any(|r| r == "IPv4 jump INPUT → OWDEPLOY-IN missing"), "{repaired:?}");
    assert_eq!(crate::firewall::reconcile().await.unwrap(), Vec::<String>::new(), "in place: nothing repaired");

    for a in [app, legacy] {
        assert!(!wget_in(a, metadata).await, "{a} reaches cloud metadata");
        assert!(!wget_in(a, private).await, "{a} reaches a private address");
        assert!(!wget_in(a, &host).await, "{a} reaches the server");
    }
    // The router on its network, by name (Docker's DNS), and the control plane before it is denied.
    assert!(wget_in(app, "http://owd-router:28092/").await, "the router is unreachable");
    assert!(wget_in(app, control).await);
    let internet = sh(&["curl", "-sf", "-o", "/dev/null", "--max-time", "5", "http://example.com/"]);
    if internet {
        assert!(wget_in(app, "http://example.com/").await, "the Internet (and DNS) is unreachable");
    } else {
        eprintln!("no Internet access from the Docker host: Internet egress not checked");
    }

    // The build network: no direct way out (no route, no outside name, nothing to the server), only the build
    // egress proxy, which reaches the public address and refuses the private ones.
    let (tx, mut rx) = mpsc::channel(1024);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let (ev, _batcher) = Events::start("e2e-build-egress".into(), tx);
    let d = crate::docker::client().unwrap();
    let session = crate::egress::Session::start(&d, "dep_E2EGB001", &BuildEgress::OPEN, &ev).await.unwrap();
    let proxy = session.args().into_iter().find(|(k, _)| k == "HTTP_PROXY").unwrap().1;
    let build_gateway =
        docker_cli(&["network", "inspect", "-f", "{{(index .IPAM.Config 0).Gateway}}", crate::builder::BUILD_NETWORK]);
    let on_build = |args: &[&str]| {
        let mut cmd =
            vec!["docker", "run", "--rm", "--network", crate::builder::BUILD_NETWORK, "curlimages/curl:8.17.0"];
        cmd.extend_from_slice(args);
        sh(&cmd)
    };
    let direct = |url: &str| on_build(&["-sf", "-o", "/dev/null", "--max-time", "5", url]);
    let proxied = |url: &str| on_build(&["-sf", "-o", "/dev/null", "--max-time", "10", "-x", &proxy, url]);
    assert!(!direct(control), "a build container reaches a public address without the proxy");
    assert!(!direct(&format!("http://{build_gateway}:28199/")), "a build container reaches the server");
    let nslookup = ["docker", "run", "--rm", "--network", crate::builder::BUILD_NETWORK, "--entrypoint", "nslookup"];
    assert!(!sh(&[&nslookup[..], &["curlimages/curl:8.17.0", "example.com"]].concat()), "outside names resolve");
    assert!(proxied(control), "the proxy does not reach a public address");
    assert!(!proxied(private), "the proxy reaches a private address");
    assert!(!proxied(metadata), "the proxy reaches cloud metadata");
    let build_rule = format!("-A OWDEPLOY-EGRESS -i {} -j REJECT", crate::builder::BUILD_BRIDGE);
    assert!(tables("iptables", &["-S", "OWDEPLOY-EGRESS"]).contains(&build_rule));
    session.finish(&ev).await;

    // The control plane's denied destinations.
    let v: serde_json::Value =
        run(Op::FirewallSync(rules("10.231.0.0/24", &[28092, 28093], &["198.51.100.7"]))).await.ok();
    eprintln!("firewall sync: {v}");
    assert!(!wget_in(app, control).await, "a denied control-plane host is reachable");
    assert!(wget_in(app, "http://owd-router:28092/").await);
    for (bin, chain) in [
        ("iptables", "DOCKER-USER"),
        ("iptables", "INPUT"),
        ("iptables", "OWDEPLOY"),
        ("iptables", "OWDEPLOY-EGRESS"),
        ("iptables", "OWDEPLOY-IN"),
        ("iptables", "OWDEPLOY-HOST"),
        ("iptables", "OWDEPLOY-SRC"),
        ("ip6tables", "DOCKER-USER"),
        ("ip6tables", "INPUT"),
        ("ip6tables", "OWDEPLOY"),
        ("ip6tables", "OWDEPLOY-EGRESS"),
        ("ip6tables", "OWDEPLOY-IN"),
        ("ip6tables", "OWDEPLOY-HOST"),
        ("ip6tables", "OWDEPLOY-SRC"),
    ] {
        eprintln!("== {bin} -S {chain}\n{}", tables(bin, &["-S", chain]));
    }
    eprintln!("== iptables -t nat -S OWDEPLOY-NAT\n{}", tables("iptables", &["-t", "nat", "-S", "OWDEPLOY-NAT"]));

    // IPv6: the same chains and jumps, the published ports edge-only (no IPv6 source listed: closed).
    let v6 = tables("ip6tables", &["-S"]);
    for rule in [
        "-A INPUT -j OWDEPLOY-IN",
        "-A DOCKER-USER -j OWDEPLOY",
        "-A OWDEPLOY -i owd+ -j OWDEPLOY-EGRESS",
        "-A OWDEPLOY-EGRESS -d fc00::/7 -j REJECT --reject-with icmp6-adm-prohibited",
        "-A OWDEPLOY-EGRESS -d fe80::/10 -j REJECT --reject-with icmp6-adm-prohibited",
        "-A OWDEPLOY-IN ! -i lo -p tcp -m tcp --dport 28092 -j OWDEPLOY-SRC",
        "-A OWDEPLOY-SRC -j DROP",
    ] {
        assert!(v6.lines().any(|l| l == rule), "missing in ip6tables: {rule}\n{v6}");
    }
    // `csf -r` style flush of IPv6 only: repaired, then in place.
    sh(&["ip6tables", "-D", "INPUT", "-j", "OWDEPLOY-IN"]);
    sh(&["ip6tables", "-F", "OWDEPLOY-EGRESS"]);
    let repaired = crate::firewall::reconcile().await.unwrap();
    assert_eq!(
        repaired,
        ["IPv6 rules of OWDEPLOY-EGRESS differ", "IPv6 jump INPUT → OWDEPLOY-IN missing"],
        "only IPv6 was broken"
    );
    assert_eq!(crate::firewall::reconcile().await.unwrap(), Vec::<String>::new());
    assert!(tables("ip6tables", &["-S", "OWDEPLOY-EGRESS"]).contains("-d fc00::/7 -j REJECT"));

    // Commands act on the application's containers only: one carrying its label without being one of them is
    // refused, by name, before anything happens.
    let impostor = "owd-e2e-impostor";
    sh(&["docker", "rm", "-f", impostor]);
    docker_ok(&[
        "run",
        "-d",
        "--name",
        impostor,
        "--label",
        &format!("dev.openwaf.deploy.resource={app}"),
        "busybox:1.37",
        "sleep",
        "600",
    ]);
    let spec = ExecSpec { resource: app.into(), service: None, command: vec!["true".into()], timeout_secs: 10 };
    let e = run(Op::Exec(spec)).await.err();
    assert!(e.contains(impostor) && e.contains("refusing"), "{e}");
    let e = run(Op::AppAction { resource: app.into(), action: AppActionKind::Stop }).await.err();
    assert!(e.contains(impostor), "{e}");
    assert_eq!(docker_cli(&["inspect", "-f", "{{.State.Running}}", impostor]), "true");
    docker_ok(&["rm", "-f", impostor]);

    for mut s in servers {
        let _ = s.kill();
        let _ = s.wait();
    }
    remove_app(app).await;
    remove_app(legacy).await;
    drop_network(new_net);
    drop_network(old_net);
    reset_firewall();
    for ns in ["ngmeta", "ngpriv", "ngcp"] {
        sh(&["ip", "netns", "del", ns]);
    }
}

/// A throwaway PKI made with the openssl CLI: an Origin CA with two certificates of `tls.e2e.test` (a renewal), the
/// edge client CA with a client certificate, and a foreign CA with its own client certificate.
struct Pki(std::path::PathBuf);

impl Pki {
    fn new() -> Pki {
        let dir = std::env::temp_dir().join(format!("owd-e2e-pki-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        const SCRIPT: &str = r#"set -e
ca() { openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout $1.key -out $1.pem -days 2 \
  -subj "/CN=$1" -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign; }
leaf() { openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout $1.key -out $1.csr -subj "/CN=$3"
  printf "subjectAltName=DNS:$3\nextendedKeyUsage=$4\n" > $1.ext
  openssl x509 -req -in $1.csr -CA $2.pem -CAkey $2.key -CAcreateserial -out $1.pem -days 2 -extfile $1.ext; }
ca originca; ca edgeca; ca rogueca
leaf app1 originca tls.e2e.test serverAuth; leaf app2 originca tls.e2e.test serverAuth
leaf client edgeca edge-node-1 clientAuth; leaf rogue rogueca edge-node-x clientAuth
"#;
        let o = Proc::new("sh").args(["-c", SCRIPT]).current_dir(&dir).output().expect("openssl");
        assert!(o.status.success(), "openssl: {}", String::from_utf8_lossy(&o.stderr));
        Pki(dir)
    }

    fn read(&self, f: &str) -> String {
        std::fs::read_to_string(self.0.join(f)).unwrap()
    }

    /// The serial of the certificate the listener on `port` serves for `sni` to the edge's client certificate.
    fn served_serial(&self, port: u16, sni: &str) -> String {
        let cmd = format!(
            "echo | openssl s_client -connect {}:{port} -servername {sni} -cert client.pem -key client.key 2>/dev/null \
             | openssl x509 -noout -serial",
            *HOST_ADDR
        );
        let o = Proc::new("sh").args(["-c", &cmd]).current_dir(&self.0).output().unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    fn serial(&self, cert: &str) -> String {
        let o = Proc::new("openssl").args(["x509", "-noout", "-serial", "-in", cert]).current_dir(&self.0).output();
        String::from_utf8_lossy(&o.unwrap().stdout).trim().to_string()
    }

    /// A client of `host` on the listener `port` that trusts the Origin CA and presents `identity` (a certificate
    /// and key pair of the PKI), reusing its connections.
    fn client(&self, host: &str, port: u16, identity: Option<&str>) -> reqwest::Client {
        let addr = std::net::SocketAddr::new(HOST_ADDR.parse().unwrap(), port);
        let mut b = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .resolve(host, addr)
            .add_root_certificate(reqwest::Certificate::from_pem(self.read("originca.pem").as_bytes()).unwrap());
        if let Some(id) = identity {
            let pem = self.read(&format!("{id}.pem")) + &self.read(&format!("{id}.key"));
            b = b.identity(reqwest::Identity::from_pem(pem.as_bytes()).unwrap());
        }
        b.build().unwrap()
    }

    fn certificate(&self, leaf: &str, id: &str, listen: u16) -> deploy_proto::msg::TlsCertificate {
        deploy_proto::msg::TlsCertificate {
            name: "app_e2etls-zone".into(),
            id: id.into(),
            listen: Some(listen),
            hosts: vec!["tls.e2e.test".into()],
            cert_pem: self.read(&format!("{leaf}.pem")),
            key_pem: self.read(&format!("{leaf}.key")),
        }
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn get(c: &reqwest::Client, url: &str) -> Result<(u16, String), String> {
    let r = c.get(url).send().await.map_err(|e| e.to_string())?;
    Ok((r.status().as_u16(), r.text().await.map_err(|e| e.to_string())?))
}

/// Requests until stopped, as the edge sends them: to the plain port while `tls` is false, then to the TLS port with
/// the edge's client certificate, each on kept-alive connections. A request that fails to be sent is sent once more,
/// as the edge's Go transport does for an idempotent request on a kept-alive connection the server closed (a router
/// reload closes idle ones). Counts (answered, sent twice, 503s, failed) with the failures' text: no 503 is expected
/// (see `router_reloads_drop_no_request`).
fn edge_loop(
    plain: reqwest::Client,
    tls: reqwest::Client,
    use_tls: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<(u64, u64, u64, Vec<String>)> {
    tokio::spawn(async move {
        let (mut ok, mut retried, mut unavailable, mut failed) = (0u64, 0u64, 0u64, Vec::new());
        while !stop.load(Ordering::SeqCst) {
            let once = async || match use_tls.load(Ordering::SeqCst) {
                false => get(&plain, &on_host("http://127.0.0.1:28111/")).await,
                true => get(&tls, "https://tls.e2e.test:28112/").await,
            };
            let mut r = once().await;
            if r.is_err() {
                retried += 1;
                r = once().await;
            }
            match r {
                Ok((200, body)) if body.trim() == "edge-tls" => ok += 1,
                Ok((503, _)) => unavailable += 1,
                other => failed.push(format!("{other:?}")),
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        (ok, retried, unavailable, failed)
    })
}

/// Edge TLS on the real router: the migration of a live application from its plain port to a TLS port that requires
/// the edge's client certificate, with requests running throughout (no gap), what the TLS port refuses, and a
/// certificate renewal that swaps the served certificate without reloading the router or failing a request.
#[tokio::test]
async fn edge_tls_listener_requires_the_edge_client_certificate() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let app = "app_e2etls";
    remove_app(app).await;
    run(Op::RouterSync(RouterConfig::default())).await.ok::<RouterState>();
    let pki = Pki::new();
    let plain_route = Route { listen: Some(28111), hosts: vec![], service: None, port: 8080, tls: false };
    let tls_route = Route { listen: Some(28112), tls: true, ..plain_route.clone() };
    let mut d = app_spec(app, "dep_E2ETLS01", 8080, None);
    d.run.command = busybox_site("edge-tls");
    d.routes = Some(vec![plain_route.clone()]);
    run(Op::DeployApp(d)).await.ok::<DeployOutput>();
    let sync = |routes: Vec<Route>, cert: Option<deploy_proto::msg::TlsCertificate>| RouterConfig {
        resources: vec![ResourceRoutes { resource: app.into(), routes }],
        tls: cert
            .map(|c| deploy_proto::msg::RouterTls { client_ca_pem: pki.read("edgeca.pem"), certificates: vec![c] }),
        ..Default::default()
    };
    let plain = reqwest::Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
    let edge = pki.client("tls.e2e.test", 28112, Some("client"));
    let (use_tls, stop) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
    let requests = edge_loop(plain.clone(), edge.clone(), use_tls.clone(), stop.clone());
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 1. The TLS port opens next to the plain one (a reload that closes no listener); once the agent reports it,
    // the edge moves to it.
    let st: RouterState = run(Op::RouterSync(sync(
        vec![plain_route.clone(), tls_route.clone()],
        Some(pki.certificate("app1", "c1", 28112)),
    )))
    .await
    .ok();
    assert_eq!((st.tls_listeners.as_slice(), st.certificates.as_slice()), (&[28112][..], &["c1".to_string()][..]));
    use_tls.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // 2. The plain port closes.
    let st: RouterState =
        run(Op::RouterSync(sync(vec![tls_route.clone()], Some(pki.certificate("app1", "c1", 28112))))).await.ok();
    assert_eq!(st.listeners, [28112]);
    tokio::time::sleep(Duration::from_millis(1000)).await;
    assert!(http("http://127.0.0.1:28111/").await.is_err(), "the plain port is closed");

    // 3. What the TLS port refuses: no client certificate, one of another CA, another name, plain HTTP.
    let url = "https://tls.e2e.test:28112/";
    assert!(get(&pki.client("tls.e2e.test", 28112, None), url).await.is_err(), "no client certificate");
    assert!(get(&pki.client("tls.e2e.test", 28112, Some("rogue")), url).await.is_err(), "a foreign client CA");
    let other = pki.client("other.e2e.test", 28112, Some("client"));
    assert!(get(&other, "https://other.e2e.test:28112/").await.is_err(), "a name without certificate");
    if let Ok((status, body)) = http("http://127.0.0.1:28112/").await {
        assert!(status != 200 && !body.contains("edge-tls"), "plain HTTP: {status} {body}");
    }

    // 4. Renewal: the same certificate name with a new certificate; the router serves it at once, its configuration
    // unchanged (no reload), while requests go on.
    assert_eq!(pki.served_serial(28112, "tls.e2e.test"), pki.serial("app1.pem"));
    let config = || docker_cli(&["exec", crate::router::CONTAINER, "cat", "/etc/owd-router/caddy.json"]);
    let before = config();
    let st: RouterState =
        run(Op::RouterSync(sync(vec![tls_route.clone()], Some(pki.certificate("app2", "c2", 28112))))).await.ok();
    assert_eq!(st.certificates, ["c2"]);
    assert_eq!(pki.served_serial(28112, "tls.e2e.test"), pki.serial("app2.pem"), "the new certificate is served");
    assert_eq!(config(), before, "a renewal does not reload the router");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    stop.store(true, Ordering::SeqCst);
    let (ok, retried, unavailable, failed) = requests.await.unwrap();
    eprintln!("migration: {ok} answered, {retried} sent again, {unavailable} 503");
    assert_eq!(unavailable, 0, "503s across the reloads");
    assert!(
        failed.is_empty(),
        "{} of {} requests failed: {:?}",
        failed.len(),
        ok as usize + failed.len(),
        &failed[..failed.len().min(5)]
    );
    assert!(ok > 0, "{ok} requests");

    // A dedicated loop across a second swap: ≥200 requests on kept-alive connections, none failing.
    let (stop2, edge2) = (Arc::new(AtomicBool::new(false)), pki.client("tls.e2e.test", 28112, Some("client")));
    let tls_on = Arc::new(AtomicBool::new(true));
    let requests = edge_loop(plain, edge2, tls_on, stop2.clone());
    tokio::time::sleep(Duration::from_millis(300)).await;
    for (leaf, id) in [("app1", "c3"), ("app2", "c4"), ("app1", "c5")] {
        run(Op::RouterSync(sync(vec![tls_route.clone()], Some(pki.certificate(leaf, id, 28112)))))
            .await
            .ok::<RouterState>();
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    stop2.store(true, Ordering::SeqCst);
    let (ok, retried, unavailable, failed) = requests.await.unwrap();
    eprintln!("renewals: {ok} answered, {retried} sent again, {unavailable} 503");
    assert_eq!((retried, unavailable), (0, 0), "a renewal closes no connection and reloads nothing");
    assert!(failed.is_empty() && ok >= 200, "{ok} answered, failed: {failed:?}");
    assert_eq!(config(), before);
    remove_app(app).await;
    run(Op::RouterSync(RouterConfig::default())).await.ok::<RouterState>();
}

/// Route changes reload the router under traffic and no request fails or gets a 503, including right after an
/// application's first route created the router's slot checks. A reload cancels the previous configuration's handlers
/// while their servers still answer; a handler whose slots one failed check had marked unavailable (the new checks run
/// before the slot-check listener opens, or meet its kept-alive connection closed by the reload) answered 503 at once.
#[tokio::test]
async fn router_reloads_drop_no_request() {
    if !enabled("OWDEPLOY_TEST_DOCKER") {
        return;
    }
    let app = "app_e2ereloads";
    let r1 = Route { listen: Some(28131), hosts: vec![], service: None, port: 8080, tls: false };
    let r2 = Route { listen: Some(28132), ..r1.clone() };
    let sync = |routes: Vec<Route>| RouterConfig {
        resources: vec![ResourceRoutes { resource: app.into(), routes }],
        ..Default::default()
    };
    let (mut ok, mut failed) = (0u64, Vec::new());
    for round in 0..5 {
        remove_app(app).await;
        run(Op::RouterSync(RouterConfig::default())).await.ok::<RouterState>();
        let mut d = app_spec(app, &format!("dep_E2ERL{round:03}"), 8080, None);
        d.routes = Some(vec![r1.clone()]);
        run(Op::DeployApp(d)).await.ok::<DeployOutput>();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let requests = tokio::spawn(async move {
            let c = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap();
            let url = on_host("http://127.0.0.1:28131/");
            let (mut ok, mut failed) = (0u64, Vec::new());
            while !stopped.load(Ordering::SeqCst) {
                // Sent once more when sending fails, as the edge's Go transport does (a reload closes idle connections).
                let mut r = get(&c, &url).await;
                if r.is_err() {
                    r = get(&c, &url).await;
                }
                match r {
                    Ok((200, body)) if body.trim() == app => ok += 1,
                    other => failed.push(format!("{other:?}")),
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            (ok, failed)
        });
        for routes in [vec![r1.clone(), r2.clone()], vec![r1.clone()], vec![r1.clone(), r2.clone()], vec![r1.clone()]] {
            tokio::time::sleep(Duration::from_millis(250)).await;
            run(Op::RouterSync(sync(routes))).await.ok::<RouterState>();
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        stop.store(true, Ordering::SeqCst);
        let (o, f) = requests.await.unwrap();
        ok += o;
        failed.extend(f);
    }
    remove_app(app).await;
    run(Op::RouterSync(RouterConfig::default())).await.ok::<RouterState>();
    assert!(
        failed.is_empty(),
        "{} of {} requests failed: {:?}",
        failed.len(),
        ok as usize + failed.len(),
        &failed[..failed.len().min(5)]
    );
    assert!(ok >= 100, "{ok} requests");
}
