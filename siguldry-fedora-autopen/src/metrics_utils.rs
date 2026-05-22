// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Metrics definitions and various utilities.
//!
//! All Prometheus metrics exported are defined here. Convenience functions to retrieve the correct
//! name/type combination are provided.

use std::time::Duration;

use anyhow::Context;
use metrics::{Counter, Gauge, Histogram};
use metrics_exporter_prometheus::PrometheusBuilder;

const AMQP_RECONNECTS: &str = "amqp_reconnects";
const MESSAGES_RECEIVED: &str = "messages_received";
const MESSAGES_ACTIVE: &str = "messages_active";
const MESSAGES_SUCCEEDED: &str = "messages_succeeded";
const MESSAGES_FAILED: &str = "messages_failed";
const MESSAGES_DROPPED: &str = "messages_dropped";

const RPMS_ACTIVE: &str = "rpms_active";
const RPMS_SIGNED: &str = "rpms_signed";
const RPMS_FAILED: &str = "rpms_failed";
const RPMS_STORAGE: &str = "rpms_artifact_size";
const RPMS_SIGN_TIME: &str = "rpms_sign_duration";

const OSTREE_SIGN_TIME: &str = "ostree_sign_duration";
const OSTREE_SIGNED: &str = "ostree_signed";
const OSTREE_FAILED: &str = "ostree_failed";
const OSTREE_SKIPPED: &str = "ostree_skipped";

const COREOS_ARTIFACTS_SIGNED: &str = "coreos_artifacts_signed";
const COREOS_SUCCEEDED: &str = "coreos_succeeded";
const COREOS_FAILED: &str = "coreos_failed";
const COREOS_SKIPPED: &str = "coreos_skipped";
const COREOS_SIGN_TIME: &str = "coreos_sign_duration";

pub(crate) fn amqp_reconnects() -> Counter {
    metrics::counter!(AMQP_RECONNECTS)
}

pub(crate) fn messages_received() -> Counter {
    metrics::counter!(MESSAGES_RECEIVED)
}

pub(crate) fn messages_active() -> Gauge {
    metrics::gauge!(MESSAGES_ACTIVE)
}

pub(crate) fn messages_succeeded() -> Counter {
    metrics::counter!(MESSAGES_SUCCEEDED)
}

pub(crate) fn messages_failed() -> Counter {
    metrics::counter!(MESSAGES_FAILED)
}

pub(crate) fn messages_dropped() -> Counter {
    metrics::counter!(MESSAGES_DROPPED)
}

pub(crate) fn rpms_active() -> Gauge {
    metrics::gauge!(RPMS_ACTIVE)
}

pub(crate) fn rpms_signed() -> Counter {
    metrics::counter!(RPMS_SIGNED)
}

pub(crate) fn rpms_failed() -> Counter {
    metrics::counter!(RPMS_FAILED)
}

pub(crate) fn rpms_storage() -> Gauge {
    metrics::gauge!(RPMS_STORAGE)
}

pub(crate) fn rpms_sign_time() -> Histogram {
    metrics::histogram!(RPMS_SIGN_TIME)
}

pub(crate) fn ostree_sign_time() -> Histogram {
    metrics::histogram!(OSTREE_SIGN_TIME)
}

pub(crate) fn ostree_signed(reference: String) -> Counter {
    metrics::counter!(OSTREE_SIGNED, "ref" => reference)
}

pub(crate) fn ostree_failed() -> Counter {
    metrics::counter!(OSTREE_FAILED)
}

pub(crate) fn ostree_skipped() -> Counter {
    metrics::counter!(OSTREE_SKIPPED)
}

pub(crate) fn coreos_artifacts_signed() -> Counter {
    metrics::counter!(COREOS_ARTIFACTS_SIGNED)
}

pub(crate) fn coreos_succeeded() -> Counter {
    metrics::counter!(COREOS_SUCCEEDED)
}

pub(crate) fn coreos_failed() -> Counter {
    metrics::counter!(COREOS_FAILED)
}

pub(crate) fn coreos_skipped() -> Counter {
    metrics::counter!(COREOS_SKIPPED)
}

pub(crate) fn coreos_sign_time() -> Histogram {
    metrics::histogram!(COREOS_SIGN_TIME)
}

/// Declare the counters, gauges, and histograms used in metrics.
pub(crate) fn init(config: &crate::config::Metrics) -> anyhow::Result<()> {
    PrometheusBuilder::new()
        .with_http_listener(config.http_listener)
        .with_recommended_naming(true)
        .upkeep_timeout(Duration::from_secs(15))
        .install()
        .context("Unable to configure Prometheus endpoint")?;
    tracing::info!(http_listener=?config.http_listener, "Prometheus HTTP exporter configured");

    metrics::counter!(
        description: "Count of times the AMQP connection has needed to be re-established",
        unit: metrics::Unit::Count,
        AMQP_RECONNECTS,
    )
    .absolute(0);

    // General message metrics
    metrics::counter!(
        description: "Count of AMQP messages received; this includes re-deliveries from requeued messages",
        unit: metrics::Unit::Count,
        MESSAGES_RECEIVED,
    ).absolute(0);
    metrics::gauge!(
        description: "The number of AMQP messages currently being processed",
        unit: metrics::Unit::Count,
        MESSAGES_ACTIVE,
    )
    .set(0);
    metrics::counter!(
        description: "Count of AMQP messages successfully processed",
        unit: metrics::Unit::Count,
        MESSAGES_SUCCEEDED,
    )
    .absolute(0);
    metrics::counter!(
        description: "Count of AMQP messages that were not processed successfully and requeued",
        unit: metrics::Unit::Count,
        MESSAGES_FAILED,
    )
    .absolute(0);
    metrics::counter!(
        description: "Count of AMQP messages that were dropped because they were invalid",
        unit: metrics::Unit::Count,
        MESSAGES_DROPPED,
    )
    .absolute(0);

    // RPM metrics
    metrics::gauge!(
        description: "The number of RPMs currently being signed",
        unit: metrics::Unit::Count,
        RPMS_ACTIVE,
    )
    .set(0);
    metrics::counter!(
        description: "The total number of RPMs that have been signed since the service started",
        unit: metrics::Unit::Count,
        RPMS_SIGNED,
    )
    .absolute(0);
    metrics::counter!(
        description: "The total number of RPM signing failures that occurred for any reason",
        unit: metrics::Unit::Count,
        RPMS_FAILED,
    )
    .absolute(0);
    metrics::gauge!(
        description: "The size, in bytes, of the RPMs being actively signed",
        unit: metrics::Unit::Bytes,
        RPMS_STORAGE,
    )
    .set(0);
    metrics::describe_histogram!(
        RPMS_SIGN_TIME,
        metrics::Unit::Seconds,
        "The time it took to run rpmsign",
    );

    // OSTree metrics
    metrics::describe_histogram!(
        OSTREE_SIGN_TIME,
        metrics::Unit::Seconds,
        "The time it took to run ostree gpg-sign",
    );
    metrics::describe_counter!(
        OSTREE_SIGNED,
        metrics::Unit::Count,
        "The count of OSTree commits signed",
    );
    metrics::counter!(
        description: "The total number of OSTree sign requests that failed and will be retried",
        unit: metrics::Unit::Count,
        OSTREE_FAILED,
    )
    .absolute(0);
    metrics::counter!(
        description: "The total number of OSTree sign requests that were skipped because they were invalid or not configured",
        unit: metrics::Unit::Count,
        OSTREE_SKIPPED,
    )
    .absolute(0);

    // CoreOS metrics
    metrics::counter!(
        description: "The total number of CoreOS artifacts that have been signed",
        unit: metrics::Unit::Count,
        COREOS_ARTIFACTS_SIGNED,
    )
    .absolute(0);
    metrics::counter!(
        description: "The total number of CoreOS sign requests that succeeded",
        unit: metrics::Unit::Count,
        COREOS_SUCCEEDED,
    )
    .absolute(0);
    metrics::counter!(
        description: "The total number of CoreOS sign requests that failed and will be retried",
        unit: metrics::Unit::Count,
        COREOS_FAILED,
    )
    .absolute(0);
    metrics::counter!(
        description: "The total number of CoreOS sign requests that were skipped because they were invalid",
        unit: metrics::Unit::Count,
        COREOS_SKIPPED,
    )
    .absolute(0);
    metrics::describe_histogram!(
        COREOS_SIGN_TIME,
        metrics::Unit::Seconds,
        "The time it took to sign a CoreOS artifact",
    );

    Ok(())
}
