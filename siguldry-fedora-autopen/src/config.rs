// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{net::SocketAddr, num::NonZeroUsize, path::PathBuf, time::Duration};

use anyhow::Context;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Application configuration.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Connection and queue settings for the AMQP consumer.
    pub amqp: Amqp,
    /// Settings related to Siguldry.
    pub siguldry: Siguldry,
    /// Configuration for both the Koji instance to use, and the tags to sign.
    #[serde(default)]
    pub koji: Koji,
    /// Configuration for how RPMs are signed.
    #[serde(default)]
    pub rpm: Rpm,
    /// Configuration for OSTree references to sign.
    #[serde(default)]
    pub ostree: Vec<Ostree>,
    /// Configuration for CoreOS artifacts to sign.
    #[serde(default)]
    pub coreos: CoreOs,
    /// Configure a Prometheus HTTP exporter.
    ///
    /// This section is optional and no exporter is configured if not provided.
    #[serde(default)]
    pub metrics: Option<Metrics>,
}

/// Connection and queue settings for the AMQP consumer.
///
/// In addition to configuring the broker location, queue name,
/// and message topics to ensure are bound to the queue, this includes
/// settings that impact the concurrency of signing operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Amqp {
    /// The AMQP URL to connect to.
    ///
    /// Note that this expects to authenticate via TLS client credentials, and as such
    /// the AMQP URL should include the `auth_mechanism=external` query parameter, e.g.
    /// `amqps://fedora:@rabbitmq.fedoraproject.org/%2Fpublic_pubsub?auth_mechanism=external`
    pub amqp_url: String,
    /// The client credentials to use when authenticating with the message broker.
    pub tls: Credentials,
    /// The queue name to consume from.
    ///
    /// If no queue name is provided, a server-generated queue name is used.
    pub queue_name: Option<String>,
    /// Queue options to use when declaring the queue.
    pub queue_options: Option<QueueDeclareOptions>,
    /// The bindings to declare for the queue, which controls which messages are delivered
    /// to the queue.
    pub bindings: Vec<Binding>,
    /// The time, in seconds, to wait before processing a message that was previously
    /// delivered, failed to process, and was requeued. This avoids spinning when a
    /// message cannot be processed due to external service issues.
    ///
    /// The default is 15 seconds.
    #[serde(default = "default_redelivery_delay")]
    pub redelivery_delay: u64,
    /// The number of AMQP messages to process concurrently.
    ///
    /// Once this limit is reached, AMQP will not deliver a new message until a
    /// message is acknowledged. This directly impacts how many signing operations
    /// happen at once. Each message will trigger _at least_ one signing request.
    ///
    /// In the case of Koji, each message is a *build* which contains many RPMs,
    /// and for each RPM in the build an `rpmsign` subprocess is run. There is a
    /// separate limit for the number of signing operations to allow. Refer to
    /// [`Siguldry`] for details.
    ///
    /// The default is 128.
    #[serde(default = "default_amqp_concurreny")]
    pub prefetch_count: u16,
}

fn default_redelivery_delay() -> u64 {
    15
}

fn default_amqp_concurreny() -> u16 {
    128
}

impl Default for Amqp {
    fn default() -> Self {
        Self {
            amqp_url: "amqps://fedora:@rabbitmq.fedoraproject.org/%2Fpublic_pubsub?auth_mechanism=external".to_string(),
            queue_name: None,
            queue_options: Default::default(),
            redelivery_delay: 15,
            prefetch_count: 128,
            bindings: vec![Binding::default()],
            tls: Credentials {
                ca_certificate: PathBuf::from("/etc/fedora-messaging/cacert.pem"),
                private_key: PathBuf::from("/etc/fedora-messaging/fedora-key.pem"),
                certificate: PathBuf::from("/etc/fedora-messaging/fedora-cert.pem"),
            },
        }
    }
}

/// The set of queue bindings to use.
///
/// The defaults are to use the `amq.topic` exchange and the following routing keys:
///
///  - `org.fedoraproject.*.buildsys.tag` - Triggers RPM signing from Koji
///  - `org.fedoraproject.*.coreos.build.request.artifacts-sign` - Triggers CoreOS artifact signing.
///  - `org.fedoraproject.*.pungi.compose.ostree` - Triggers OSTree commit signing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    /// The AMQP exchange to bind to.
    pub exchange: String,
    /// The routing keys to use when binding to the exchange.
    pub routing_keys: Vec<String>,
}

impl Default for Binding {
    fn default() -> Self {
        Self {
            exchange: "amq.topic".to_string(),
            routing_keys: vec![
                "org.fedoraproject.*.buildsys.tag".to_string(),
                "org.fedoraproject.*.coreos.build.request.artifacts-sign".to_string(),
                "org.fedoraproject.*.pungi.compose.ostree".to_string(),
            ],
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueDeclareOptions {
    pub passive: bool,
    pub durable: bool,
    pub exclusive: bool,
    pub auto_delete: bool,
    pub nowait: bool,
}

impl From<QueueDeclareOptions> for lapin::options::QueueDeclareOptions {
    fn from(value: QueueDeclareOptions) -> lapin::options::QueueDeclareOptions {
        Self {
            passive: value.passive,
            durable: value.durable,
            exclusive: value.exclusive,
            auto_delete: value.auto_delete,
            nowait: value.nowait,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub ca_certificate: PathBuf,
    pub private_key: PathBuf,
    pub certificate: PathBuf,
}

impl Credentials {
    /// Fix up any relative paths in the configuration file to use the provided credentials directory.
    ///
    /// # Errors
    ///
    /// If the referenced files don't exist, an error is returned.
    pub fn with_credentials_dir(
        &mut self,
        credentials_dir: &std::path::Path,
    ) -> anyhow::Result<()> {
        if self.private_key.is_absolute() {
            tracing::warn!(
                private_key = self.private_key.display().to_string(),
                "Path to private key file is absolute; consider using systemd credentials"
            );
        } else {
            self.private_key = credentials_dir.join(&self.private_key);
            if !self.private_key.exists() {
                return Err(anyhow::anyhow!(
                    "No private key file named '{}' found in credentials directory",
                    self.private_key.display()
                ));
            }
        }
        if !self.certificate.is_absolute() {
            self.certificate = credentials_dir.join(&self.certificate);
            if !self.certificate.exists() {
                return Err(anyhow::anyhow!(
                    "No certificate file named '{}' found in credentials directory",
                    self.certificate.display()
                ));
            }
        }
        if !self.ca_certificate.is_absolute() {
            self.ca_certificate = credentials_dir.join(&self.ca_certificate);
            if !self.ca_certificate.exists() {
                return Err(anyhow::anyhow!(
                    "No CA certificate file named '{}' found in credentials directory",
                    self.ca_certificate.display()
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Koji {
    /// The path to the Koji XMLRPC server; for example `https://koji.fedoraproject.org/kojihub`.
    pub url: String,
    /// The instance name of this Koji; used to filter out AMQP messages from other Koji instances
    ///
    /// For example, koji.fedoraproject.org would use the value "primary".
    pub instance: String,
    /// Defines how to authenticate with Koji.
    pub auth: KojiAuthentication,
    #[serde(default)]
    pub readonly: bool,
    /// A list of tags which we should watch and autosign.
    pub tags: Vec<Tag>,
}

impl Default for Koji {
    fn default() -> Self {
        Self {
            url: "https://koji.fedoraproject.org/kojihub".to_string(),
            instance: "primary".to_string(),
            readonly: false,
            auth: Default::default(),
            tags: Default::default(),
        }
    }
}

impl Koji {
    /// Find the tag configuration for a source tag name, if it exists.
    ///
    /// Build can land in a generic per-release tag (e.g. f45-signing-pending) or
    /// a user-created side tag configured to merge into a parent tag. This handles
    /// both cases and returns a reference to the tag with the signing key information
    /// as well as the tag the build should be moved to when signing is completed.
    pub fn match_tag(&self, from_tag_name: &str) -> Option<(&Tag, String)> {
        // The simple case where it's not a side tag
        if let Some(tag) = self.tags.iter().find(|t| t.from == from_tag_name) {
            return Some((tag, tag.to.clone()));
        }

        // Each tag can optionally configure a sidetag pattern to match
        for tag in self.tags.iter() {
            if let Some(sidetag) = &tag.sidetags
                && let Some(to_tag) = sidetag
                    .from_regex
                    .captures(from_tag_name)
                    .and_then(|captures| captures.name("sidetag"))
                    .map(|m| sidetag.to_template.replace("<sidetag>", m.as_str()))
            {
                return Some((tag, to_tag));
            }
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "authmethod")]
#[serde(rename_all = "lowercase")]
pub enum KojiAuthentication {
    Kerberos {
        /// The kerberos principal to authenticate with; for example someone@EXAMPLE.ORG
        principal: String,
        /// Path to the keytab file.
        keytab: Option<PathBuf>,
        /// Path to the ccache file/dir.
        ccache: Option<PathBuf>,
    },
}

impl Default for KojiAuthentication {
    fn default() -> Self {
        Self::Kerberos {
            principal: "someone@EXAMPLE.COM".to_string(),
            keytab: None,
            ccache: None,
        }
    }
}

/// Define a tag in Koji that we should auto-sign when packages are added.
///
/// When a build is tagged into the "from" tag, we will sign it using the configured
/// key, then move the build to the "to" tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tag {
    /// The name of the source tag in koji
    pub from: String,
    /// The name of the destination tag in koji
    pub to: String,
    /// The name of the key in Siguldry to sign with
    pub siguldry_key: String,
    /// The name of the OpenPGP certificate associated with the key that
    /// should be used when signing.
    pub siguldry_openpgp_cert: String,
    /// The PKCS #11 URI to use for IMA signatures.
    ///
    /// If not set, the RPM will not be signed for IMA. Requires RPM 6.1+.
    pub file_signing_key: Option<Ima>,
    /// List of usernames who are allowed to apply a tag for signing;
    /// if a user not on this list applies the tag, it will not be signed.
    pub trusted_taggers: Vec<String>,
    /// An optional side tag definition.
    ///
    /// Builds that match the side tag pattern will also be signed by the key
    /// used for this tag.
    pub sidetags: Option<SideTag>,
}

/// IMA signing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ima {
    /// The name of the key in Siguldry to use for IMA signatures
    pub siguldry_key: String,
    /// The name of the X.509 certificate associated with the key to use.
    ///
    /// The Subject Key ID from this certificate is embedded in the IMA structure
    /// users
    pub siguldry_x509_cert: String,
}

/// Sidetags are build tags branched off a base tag.
///
/// This configuration allows the admin to define a regular expression to match
/// tag names, which will be signed using the key configured on the parent tag.
///
/// Side tags contain the base tag's name and the sequence ID of the side tag.
/// Koji allows these to be prefixed, suffixed, and split with arbitrary strings.
/// The typical format used in Fedora is in the form:
///
/// `<basetag>-side-<seq_id>`
///
/// This tag is where developers perform their builds. When they submit the tag to
/// Bodhi as an update, Bodhi tags the builds into a tag in the format:
///
/// `<basetag>-side-<seq_id>-signing-pending`
///
/// These are the tags this service responds to; once every build is signed, we tag
/// the builds into:
///
/// `<basetag>-side-<seq_id>-testing-pending`
///
/// An example tag heirarchy would be an `f44-build` base tag, so a sidetag would look
/// like `f44-build-side-42`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SideTag {
    /// A regular expression that matches the side tag name to auto-sign.
    ///
    /// The regular expression provided *MUST* have a capture group named "sidetag".
    /// The value matched by this group is used in the destination sidetag template.
    ///
    /// An example would be "(?P<sidetag>f44-build-side-[1-9][0-9]*)-signing-pending"
    #[serde(
        serialize_with = "serialize_regex",
        deserialize_with = "deserialize_regex"
    )]
    pub from_regex: Regex,
    /// The suffix to append to the above regular expression when moving signed builds
    /// from the source tag to the destination tag.
    ///
    /// For example, setting this to `-testing-pending` would, assuming the example
    /// regex is used, move the build from `f44-build-side-42-signing-pending` to
    /// `f44-build-side-42-testing-pending`.
    ///
    /// A template for the destination tag.
    ///
    /// The template should contain a `<sidetag>` variable which is replaced with the
    /// value matched by the `sidetag` group in the `from_regex` setting. For example:
    ///
    /// ```toml
    /// from_regex = "(?P<sidetag>f44-build-side-[1-9][0-9]*)-signing-pending"
    /// to_template = "<sidetag>-testing-pending"
    /// ```
    ///
    /// Will move a build from `f44-build-side-42-signing-pending` to
    /// `f44-build-side-42-testing-pending`.
    pub to_template: String,
}

fn serialize_regex<S>(regex: &Regex, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(regex.as_str())
}

fn deserialize_regex<'de, D>(deserializer: D) -> Result<Regex, D::Error>
where
    D: Deserializer<'de>,
{
    let regex = Regex::new(String::deserialize(deserializer)?.as_str())
        .map_err(serde::de::Error::custom)?;
    if !regex
        .capture_names()
        .any(|capture| matches!(capture, Some("sidetag")))
    {
        Err(serde::de::Error::custom(
            "The regular expression MUST contain a 'sidetag' group (e.g. (?P<sidetag>...)",
        ))
    } else {
        Ok(regex)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rpm {
    /// The underlying tool to use for OpenPGP signatures.
    pub signing_tool: SigningTool,
    /// If true, when signing RPMv6 packages, an RPM v4 header signature will also be
    /// included. This is equivalent to passing the --rpmv4 flag to rpmsign.
    pub with_rpmv4: bool,

    /// If set, a limit is applied to the amount of temporary storage used for downloaded
    /// RPMs. The value is provided in MiB.
    ///
    /// Because the systemd unit makes use of a private tmpfs, and because some RPMs can
    /// be quite large, you may wish to set an upper limit on the amount of temporary
    /// storage used to avoid "No more space on device" type errors.
    ///
    /// This value must be larger than the largest RPM you wish to sign; if an RPM is
    /// larger the message will be requeued for eternity until the limit is raised or
    /// the message is dropped.
    ///
    /// `rpmsign` will also conditionally make a temporary copy of the RPM when signing
    /// if it decides the signature will not fit in the existing reserved space. This
    /// means that the available tmpfs space should be about twice as much as what this
    /// value is set to. You may want to adjust the `tmp.mount` options.
    pub storage_limit_mb: Option<usize>,

    /// The location to use as a working directory when downloading and signing RPMs.
    ///
    /// RPMs can be quite large, and `rpmsign` requires the entire RPM to be present even
    /// though it only signs the header. Additionally, `rpmsign` may make a temporary copy
    /// in $TMPDIR while signing. All this can lead to enormous memory usage when your tmpfs
    /// is backed by memory.
    ///
    /// The default location is /var/tmp/, which is typically backed by persistent storage and
    /// kept tidy by systemd. As all the files _should_ be short-lived, this shouldn't be an
    /// issue. The amount of space used in this directory can be controlled by `storage_limit_mb`,
    /// and is recommended as that also indirectly controls the amount of space `rpmsign` uses
    /// via its copies in the memory-backed /tmp/ directory.
    #[serde(default = "default_rpm_working_dir")]
    pub working_directory: PathBuf,

    /// The amount of time to wait for a build to be signed successfully; if a timeout is hit
    /// the message is requeued and attempted later. Note that when using IMA signing, the time
    /// it takes to sign scales proportionally with the number of files in the RPM.
    ///
    /// Defaults to 1 hour.
    #[serde(default = "default_rpm_timeout")]
    pub timeout: Duration,
}

fn default_rpm_timeout() -> Duration {
    Duration::from_secs(60 * 60)
}

fn default_rpm_working_dir() -> PathBuf {
    PathBuf::from("/var/tmp/")
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningTool {
    Sq,
    #[default]
    Gpg,
}

impl Default for Rpm {
    fn default() -> Self {
        Self {
            signing_tool: Default::default(),
            with_rpmv4: true,
            storage_limit_mb: None,
            working_directory: default_rpm_working_dir(),
            timeout: default_rpm_timeout(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreOs {
    pub aws_region: String,
    pub aws_bucket: String,
    pub aws_access_key: String,
    pub aws_access_secret: String,
    pub signing_tool: SigningTool,
    pub keys: Vec<CoreOsKey>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreOsKey {
    /// The major build version (45, 46, etc.)
    pub build_version: usize,
    /// The Siguldry key to sign with
    pub siguldry_key: String,
    /// The name of the associated OpenPGP certificate to use.
    pub siguldry_openpgp_cert: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Siguldry {
    pub client_proxy_socket: PathBuf,
    /// Limit the number of concurrent connections to the Siguldry client proxy.
    ///
    /// This limit should match, or be slightly less than, the `MaxConnections` setting on the
    /// `siguldry-client-proxy.socket` systemd socket unit to ensure the service doesn't repeatedly
    /// try to start new connections that systemd will reject, which leads to processing delays and
    /// unnecessary message requeuing.
    ///
    /// The other setting that impacts concurrency is the [`Amqp::prefetch_count`] option. Signing
    /// tasks are spawned for each message, and each signing task results in one or more connections
    /// to the Siguldry client proxy.
    #[serde(default = "default_signing_concurreny")]
    pub concurrency: NonZeroUsize,
}

fn default_signing_concurreny() -> NonZeroUsize {
    NonZeroUsize::new(128).expect("Set a non-zero default")
}

impl Default for Siguldry {
    fn default() -> Self {
        Self {
            client_proxy_socket: PathBuf::from(
                "/run/siguldry-client-proxy/siguldry-client-proxy.socket",
            ),
            concurrency: default_signing_concurreny(),
        }
    }
}

impl std::fmt::Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            toml::ser::to_string_pretty(&self).unwrap_or_default()
        )
    }
}

fn private_load_config<T>(path: &std::path::Path) -> anyhow::Result<T>
where
    T: Default + std::fmt::Display + serde::de::DeserializeOwned,
{
    let config = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read from path {path:?}"))?;
    tracing::info!(path=%path.display(), "Read from configuration file");
    toml::from_str(&config)
        .inspect_err(|error| {
            eprintln!("Failed to parse configuration loaded from {path:?}:\n{error}");
            eprintln!("Example config file:\n\n{}", T::default());
        })
        .context("configuration file is invalid")
}

/// Load the configuration with fallback options.
///
/// If `path` is [`None`], the `default` path, which should be relative to CONFIGURATION_DIRECTORY, is
/// checked.  If the default config doesn't exist, the [`Default`] implementation is returned. It's
/// expected that CONFIGURATION_DIRECTORY is set via systemd.
///
/// # Errors
///
/// In the event that one of the config files exists, but is invalid, an error is returned.
pub fn load_config<T>(path: Option<PathBuf>, default: &std::path::Path) -> anyhow::Result<T>
where
    T: Default + std::fmt::Display + serde::de::DeserializeOwned,
{
    path.or_else(|| {
        std::env::var("CONFIGURATION_DIRECTORY")
            .inspect_err(|error| {
                tracing::warn!(
                    ?error,
                    "CONFIGURATION_DIRECTORY environment variable isn't readable"
                );
            })
            .map(PathBuf::from)
            .ok()
            .map(|base_path| base_path.join(default))
            .filter(|path| path.is_file())
    })
    .map_or_else(
        || {
            tracing::warn!("No configuration file found; using defaults");
            Ok(T::default())
        },
        |path| {
            tracing::info!(?path, "Attempting to load configuration");
            private_load_config::<T>(&path)
        },
    )
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Ostree {
    /// The OSTree ref this configuration is for.
    pub reference: String,
    /// The directory containing the ostree.
    pub directory: PathBuf,
    /// The name of the key in Siguldry to sign with.
    pub siguldry_key: String,
    /// The name of the OpenPGP certificate associated with the key that
    /// should be used when signing.
    pub siguldry_openpgp_cert: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// The interface and port to serve Prometheus metrics from.
    ///
    /// By default, this is the IPv6 loopback address on port 9000, "::1:9000".
    pub http_listener: SocketAddr,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            http_listener: "::1:9000"
                .parse()
                .expect("Default listen address must be valid"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tag(from: &str, to: &str) -> Tag {
        Tag {
            from: from.to_string(),
            to: to.to_string(),
            siguldry_key: "demo".to_string(),
            siguldry_openpgp_cert: "demo-openpgp".to_string(),
            file_signing_key: None,
            trusted_taggers: vec!["bodhi".to_string()],
            sidetags: None,
        }
    }

    fn sample_sidetag_tag(from: &str, to: &str, regex: &str, template: &str) -> Tag {
        let mut t = sample_tag(from, to);
        t.sidetags = Some(SideTag {
            from_regex: Regex::new(regex).unwrap(),
            to_template: template.to_string(),
        });
        t
    }

    // Assert the internal tagging for the structure matches robosignatory
    #[test]
    fn kerberos_authmethod_deserializes() {
        let toml_str = r#"
            authmethod = "kerberos"
            principal = "someone@EXAMPLE.ORG"
        "#;
        let parsed: KojiAuthentication = toml::from_str(toml_str).unwrap();
        match parsed {
            KojiAuthentication::Kerberos {
                principal,
                keytab,
                ccache,
            } => {
                assert_eq!(principal, "someone@EXAMPLE.ORG");
                assert!(keytab.is_none());
                assert!(ccache.is_none());
            }
        }
    }

    #[test]
    fn unknown_authmethod_is_rejected() {
        let toml_str = r#"
            authmethod = "anonymous"
        "#;
        let err = toml::from_str::<KojiAuthentication>(toml_str).unwrap_err();
        assert!(
            err.to_string().contains("anonymous") || err.to_string().contains("variant"),
            "unexpected error: {err}"
        );
    }

    // We reject unknown keys in the config
    #[test]
    fn unknown_keys_in_koji_are_rejected() {
        let toml_str = r#"
            url = "https://example.com/kojihub"
            instance = "primary"
            tags = []
            inquisition = "nobody"

            [auth]
            authmethod = "kerberos"
            principal = "someone@EXAMPLE.ORG"
        "#;
        let err = toml::from_str::<Koji>(toml_str).unwrap_err();
        assert!(
            err.to_string().contains("inquisition"),
            "unexpected error: {err}"
        );
    }

    // We reject regex in sidetags without the necessary named group
    #[test]
    fn sidetag_regex_without_named_group_is_rejected() {
        let toml_str = r#"
            from_regex = "f44-build-side-[1-9][0-9]*-signing-pending"
            to_template = "<sidetag>-testing-pending"
        "#;
        let err = toml::from_str::<SideTag>(toml_str).unwrap_err();
        assert!(
            err.to_string().contains("sidetag"),
            "expected error to mention the missing 'sidetag' group: {err}"
        );
    }

    #[test]
    fn sidetag_regex_with_named_group_is_accepted() {
        let toml_str = r#"
            from_regex = "(?P<sidetag>f44-build-side-[1-9][0-9]*)-signing-pending"
            to_template = "<sidetag>-testing-pending"
        "#;
        let parsed: SideTag = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.to_template, "<sidetag>-testing-pending");
        assert!(
            parsed
                .from_regex
                .is_match("f44-build-side-9-signing-pending")
        );
    }

    // Invalid regex gets caught when parsing the config
    #[test]
    fn invalid_regex_syntax_is_rejected() {
        let toml_str = r#"
            from_regex = "(?P<sidetag>"
            to_template = "<sidetag>-testing-pending"
        "#;
        let err = toml::from_str::<SideTag>(toml_str).unwrap_err();
        assert!(err.to_string().contains("regex parse error"));
    }

    #[test]
    fn koji_match_tag_returns_none_when_no_rule_matches() {
        let koji_config = Koji {
            tags: vec![sample_tag(
                "f45-signing-pending",
                "f45-updates-testing-pending",
            )],
            ..Default::default()
        };
        assert!(koji_config.match_tag("rawhide-build").is_none());
    }

    #[test]
    fn koji_match_tag_direct_match_returns_configured_destination() {
        let koji_config = Koji {
            tags: vec![sample_tag(
                "f45-signing-pending",
                "f45-updates-testing-pending",
            )],
            ..Default::default()
        };
        let (matched, tag_to) = koji_config.match_tag("f45-signing-pending").unwrap();
        assert_eq!(matched.from, "f45-signing-pending");
        assert_eq!(tag_to, "f45-updates-testing-pending");
    }

    #[test]
    fn koji_match_tag_sidetag_substitutes_template() {
        let koji_config = Koji {
            tags: vec![sample_sidetag_tag(
                "f45-signing-pending",
                "f45-updates-testing-pending",
                "(?P<sidetag>f45-build-side-[1-9][0-9]*)-signing-pending",
                "<sidetag>-testing-pending",
            )],
            ..Default::default()
        };

        let (_matched, tag_to) = koji_config
            .match_tag("f45-build-side-42-signing-pending")
            .unwrap();
        assert_eq!(tag_to, "f45-build-side-42-testing-pending");
    }

    #[test]
    fn load_example_config() -> anyhow::Result<()> {
        let example_conf_path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.toml.example");
        let example_conf = std::fs::read_to_string(&example_conf_path)?;
        toml::de::from_str::<super::Config>(&example_conf)?;

        Ok(())
    }
}
