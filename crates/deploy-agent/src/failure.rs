//! A failed deployment: the message the control plane shows as its error and, when the agent can tell where it
//! failed, its cause (`Outcome::Error::cause`, PROTOCOL.md §5). The cause is named where the failure happens (the
//! Git helper's output, the build's output, an Engine call, the health check, the router, the Compose checks); code
//! that cannot classify a failure passes it on without one.

use std::collections::BTreeMap;

use deploy_proto::msg::Cause;

use crate::events::Events;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub message: String,
    pub cause: Option<Cause>,
}

impl From<String> for Failure {
    fn from(message: String) -> Failure {
        Failure { message, cause: None }
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Failure {
        Failure { message: message.to_string(), cause: None }
    }
}

impl Failure {
    /// A failure with cause `code` (a [`deploy_proto::msg::cause`] constant) and its parameters.
    pub fn new<'a>(
        code: &'static str,
        params: impl IntoIterator<Item = (&'a str, String)>,
        message: impl Into<String>,
    ) -> Failure {
        let params: BTreeMap<String, String> = params.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        Failure { message: message.into(), cause: Some(Cause { code: code.to_string(), params }) }
    }

    /// The same failure with `prefix` before its message (`router: …`).
    pub fn prefixed(self, prefix: &str) -> Failure {
        Failure { message: format!("{prefix}{}", self.message), ..self }
    }

    /// The failure without the operation's registry credentials, in its message and in every parameter value
    /// ([`Events::scrub`]).
    pub fn scrubbed(self, ev: &Events) -> Failure {
        let cause = self
            .cause
            .map(|c| Cause { params: c.params.into_iter().map(|(k, v)| (k, ev.scrub(&v))).collect(), code: c.code });
        Failure { message: ev.scrub(&self.message), cause }
    }

    /// The cause's code, if any.
    #[cfg(test)]
    pub fn code(&self) -> Option<&str> {
        self.cause.as_ref().map(|c| c.code.as_str())
    }

    /// The value of the cause's parameter `name`.
    #[cfg(test)]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.cause.as_ref()?.params.get(name).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use deploy_proto::msg::RegistryAuth;
    use deploy_proto::msg::cause::GIT_AUTH_FAILED;

    use super::*;

    /// A cause never carries the operation's registry credentials, in its parameters as in its message.
    #[tokio::test]
    async fn scrubbing_covers_the_message_and_every_parameter() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let (ev, _batcher) = Events::start("t".into(), tx);
        ev.redact_with(&[RegistryAuth {
            server: "ghcr.io".into(),
            username: "u".into(),
            password: "s3cr3t-tok".into(),
        }]);
        let f = Failure::new(GIT_AUTH_FAILED, [("host", "x s3cr3t-tok".to_string())], "failed with s3cr3t-tok")
            .scrubbed(&ev);
        assert!(!f.message.contains("s3cr3t-tok"), "{}", f.message);
        assert!(!f.param("host").unwrap().contains("s3cr3t-tok"), "{f:?}");
        assert_eq!(f.code(), Some(GIT_AUTH_FAILED));
    }
}
