// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Utilities to work with Koji for RPM signing.

use std::{
    ffi::CStr,
    path::PathBuf,
    thread::{self, JoinHandle},
};

use anyhow::Context;
use pyo3::{
    FromPyObject, Python,
    types::{PyAnyMethods, PyModule},
};
use tokio::sync::{mpsc, oneshot};
use tracing::instrument;

use crate::config::Koji;

const KOJI: &CStr = pyo3::ffi::c_str!(include_str!("koji_utils.py"));

/// Operations performed against Koji.
///
/// This trait abstracts away the Python actor so testing is easier.
pub trait KojiOps: Clone + Send + Sync + 'static {
    /// Retrieve the details for all the RPMs within a build.
    fn build_info(
        &self,
        build_id: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<Build>> + Send;

    /// Add a signature header to the RPM in Koji.
    fn add_signature(
        &self,
        rpm_id: i64,
        expected_sigkey: String,
        signed_package: PathBuf,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;

    /// Move the build from one tag to another.
    ///
    /// Returns the task ID of the move operation.
    fn move_build(
        &self,
        build_id: i64,
        expected_sigkey: String,
        tag_from: String,
        tag_to: String,
    ) -> impl std::future::Future<Output = anyhow::Result<i64>> + Send;
}

/// An RPM that is part of a build.
#[derive(Debug, Clone, Default, FromPyObject)]
pub struct Rpm {
    pub id: i64,
    pub draft: bool,
    pub epoch: Option<i64>,
    pub name: String,
    pub version: String,
    pub release: String,
    pub size: u64,
    pub url: String,
    pub sha256sum: String,
    pub existing_sigkeys: Vec<String>,
}

#[derive(Debug, Clone, Default, FromPyObject)]
pub struct TagEvent {
    pub create_event: i64,
    pub creator_name: String,
    pub tag_name: String,
}

/// A build in Koji.
///
/// A single build can have many RPMs, and we have to sign all of them before moving the build
/// from one tag to another.
#[derive(Debug, Clone, Default, FromPyObject)]
pub struct Build {
    pub id: i64,
    pub tag_history: Vec<TagEvent>,
    pub rpms: Vec<Rpm>,
}

impl Build {
    pub(crate) fn active_tag(&self) -> Option<TagEvent> {
        self.tag_history
            .iter()
            .max_by_key(|e| e.create_event)
            .cloned()
    }
}

#[derive(Debug)]
enum KojiRequest {
    BuildInfo {
        build_id: i64,
    },
    AddSignature {
        rpm_id: i64,
        expected_sigkey: String,
        signed_package: PathBuf,
    },
    MoveBuild {
        build_id: i64,
        expected_sigkey: String,
        tag_from: String,
        tag_to: String,
    },
}

#[derive(Debug)]
enum KojiResponse {
    BuildInfo(anyhow::Result<Build>),
    AddSignature(anyhow::Result<()>),
    /// Returns the task ID of the move task
    MoveBuild(anyhow::Result<i64>),
}

#[derive(Debug)]
pub struct KojiActor {
    python_thread: JoinHandle<Result<(), anyhow::Error>>,
    request_tx: mpsc::Sender<(KojiRequest, oneshot::Sender<KojiResponse>)>,
    readonly: bool,
}

impl KojiActor {
    pub fn new(config: Koji) -> anyhow::Result<Self> {
        let (request_tx, mut rx) = mpsc::channel::<(KojiRequest, oneshot::Sender<KojiResponse>)>(2);
        let client = Python::attach(|py| {
            let module = PyModule::from_code(py, KOJI, c"koji_utils.py", c"")?;
            match &config.auth {
                crate::config::KojiAuthentication::Kerberos {
                    principal,
                    keytab,
                    ccache,
                } => module
                    .getattr("Client")?
                    .call(
                        (
                            &config.url,
                            principal,
                            keytab.as_ref(),
                            ccache.as_ref(),
                            config.readonly,
                        ),
                        None,
                    )
                    .context("Failed to create Koji client")
                    .map(|obj| obj.unbind()),
            }
        })?;

        if config.readonly {
            tracing::info!(
                config.readonly,
                "All Koji operations will be read-only and no authentication will be attempted"
            );
        }

        let python_thread = thread::Builder::new()
            .spawn(move || {
                while let Some((request, respond_to)) = rx.blocking_recv() {
                    let response = Python::attach(|py| {
                        // Be careful to not break out of this receive loop on errors.
                        let bound_client = client.bind(py);
                        match request {
                            KojiRequest::BuildInfo { build_id } => {
                                let result = bound_client
                                    .call_method1("build_info", (build_id,))
                                    .context("Koji build_info call failed")
                                    .and_then(|obj| {
                                        obj.extract::<Build>()
                                            .context("Failed to extract Koji Build")
                                    });
                                KojiResponse::BuildInfo(result)
                            }
                            KojiRequest::AddSignature {
                                rpm_id,
                                expected_sigkey,
                                signed_package,
                            } => {
                                let result = bound_client
                                    .call_method1(
                                        "add_signature",
                                        (rpm_id, expected_sigkey, signed_package),
                                    )
                                    .context("Koji add_signature call failed")
                                    .map(|_| ());
                                KojiResponse::AddSignature(result)
                            }
                            KojiRequest::MoveBuild {
                                build_id,
                                expected_sigkey,
                                tag_from,
                                tag_to,
                            } => {
                                let result = bound_client
                                    .call_method1(
                                        "move_build",
                                        (build_id, expected_sigkey, tag_from, tag_to),
                                    )
                                    .context("Koji move_build call failed")
                                    .and_then(|obj| {
                                        obj.extract::<i64>()
                                            .context("Failed to extract move_build task ID")
                                    });
                                KojiResponse::MoveBuild(result)
                            }
                        }
                    });

                    let _ = respond_to.send(response);
                }
                Ok::<_, anyhow::Error>(())
            })
            .context("Failed to spawn Koji request thread")?;

        Ok(Self {
            python_thread,
            request_tx,
            readonly: config.readonly,
        })
    }

    pub fn handle(&self) -> impl KojiOps {
        KojiHandle {
            inner: self.request_tx.clone(),
            readonly: self.readonly,
        }
    }

    pub fn shutdown(self) -> anyhow::Result<()> {
        let thread = self.python_thread;

        // Drop our handle; the thread won't join until all other handles are also dropped.
        let handle = self.request_tx;
        drop(handle);

        thread
            .join()
            .map_err(|error| anyhow::anyhow!("Unable to join python thread: {error:?}"))?
            .context("Python thread did not shut down cleanly")?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct KojiHandle {
    inner: mpsc::Sender<(KojiRequest, oneshot::Sender<KojiResponse>)>,
    readonly: bool,
}

impl KojiOps for KojiHandle {
    #[instrument(skip(self), err)]
    async fn build_info(&self, build_id: i64) -> anyhow::Result<Build> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .send((KojiRequest::BuildInfo { build_id }, tx))
            .await?;

        match rx.await.context("Python actor failed to respond")? {
            KojiResponse::BuildInfo(response) => response,
            other => panic!("Programming error; actor responded with the wrong call: {other:?}"),
        }
    }

    #[instrument(skip(self), err)]
    async fn add_signature(
        &self,
        rpm_id: i64,
        expected_sigkey: String,
        signed_package: PathBuf,
    ) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .send((
                KojiRequest::AddSignature {
                    rpm_id,
                    expected_sigkey,
                    signed_package,
                },
                tx,
            ))
            .await?;

        match rx.await.context("Python actor failed to respond")? {
            KojiResponse::AddSignature(response) => {
                if self.readonly {
                    tracing::info!(
                        ?response,
                        "Completed Koji add_signature() call, but operating in read-only mode"
                    );
                }
                response
            }
            other => panic!("Programming error; actor responded with the wrong call: {other:?}"),
        }
    }

    #[instrument(skip(self), err)]
    async fn move_build(
        &self,
        build_id: i64,
        expected_sigkey: String,
        tag_from: String,
        tag_to: String,
    ) -> anyhow::Result<i64> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .send((
                KojiRequest::MoveBuild {
                    build_id,
                    expected_sigkey,
                    tag_from,
                    tag_to,
                },
                tx,
            ))
            .await?;

        match rx.await.context("Python actor failed to respond")? {
            KojiResponse::MoveBuild(response) => {
                if self.readonly {
                    tracing::info!(
                        "Completed Koji move_build() call, but operating in read-only mode"
                    );
                }
                response
            }
            other => panic!("Programming error; actor responded with the wrong call: {other:?}"),
        }
    }
}
