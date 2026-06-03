// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::Context;
use lapin::{
    BasicProperties, Channel, Connection, ConnectionProperties,
    message::Delivery,
    options::{
        BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions,
        BasicQosOptions, ConfirmSelectOptions, QueueBindOptions,
    },
    tcp::{OwnedIdentity, OwnedTLSConfig},
    types::{AMQPValue, FieldTable},
};
use siguldry::protocol::Key;
use tokio::{sync::Semaphore, task::JoinSet};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{Level, instrument};

use crate::{PgpConfig, config::Config, coreos, koji::KojiOps, ostree, rpmsign};

// Handle a single connection.
pub async fn connect_and_consume<K: KojiOps>(
    config: Arc<crate::config::Config>,
    http_client: reqwest::Client,
    pgp_home: Arc<PgpConfig>,
    signing_keys: Arc<HashMap<String, Key>>,
    koji_handle: K,
    halt_token: CancellationToken,
) -> anyhow::Result<()> {
    let connection = tokio::select! {
        connection = connect(&config.amqp) => {
            connection
        }
        _ = halt_token.cancelled() => {
            tracing::info!("Aborting connection attempt and shutting down");
            return Ok(());
        }
    }
    .context("Failed to connect to the message broker")?;

    let channel = connection
        .create_channel()
        .await
        .context("Failed to create AMQP channel")?;
    tracing::debug!(channel_id = channel.id(), "Channel established");
    channel
        .basic_qos(config.amqp.prefetch_count, BasicQosOptions::default())
        .await
        .context("Failed to set channel QoS")?;

    let queue_name = config.amqp.queue_name.clone().unwrap_or_default().into();
    let queue_options = config.amqp.queue_options.clone().unwrap_or_default().into();
    let queue = channel
        .queue_declare(queue_name, queue_options, FieldTable::default())
        .await
        .context("Failed to declare queue")?;
    tracing::info!(queue = queue.name().as_str(), "Queue declared");
    for binding in &config.amqp.bindings {
        for routing_key in &binding.routing_keys {
            channel
                .queue_bind(
                    queue.name().to_owned(),
                    binding.exchange.clone().into(),
                    routing_key.clone().into(),
                    QueueBindOptions::default(),
                    FieldTable::default(),
                )
                .await?;
            tracing::info!(
                queue = queue.name().as_str(),
                exchange = binding.exchange,
                routing_key,
                "Declared queue binding"
            );
        }
    }
    tracing::info!("Successfully declared all queue bindings");

    tracing::info!(
        "Signing will allow at most {} operations concurrently",
        config.siguldry.concurrency.get()
    );
    let concurrency = Arc::new(Semaphore::new(config.siguldry.concurrency.get()));
    let koji_signer = rpmsign::KojiSigner::new(
        Arc::clone(&config),
        Arc::clone(&concurrency),
        Arc::clone(&pgp_home),
        Arc::clone(&signing_keys),
        http_client.clone(),
        koji_handle.clone(),
    );
    let ostree_signer = crate::ostree::OstreeSigner::new(
        Arc::clone(&config),
        Arc::clone(&concurrency),
        Arc::clone(&pgp_home),
        Arc::clone(&signing_keys),
    );
    let coreos_signer = coreos::CoreOsSigner::new(
        Arc::clone(&config),
        Arc::clone(&concurrency),
        http_client.clone(),
        Arc::clone(&pgp_home),
        Arc::clone(&signing_keys),
    )?;
    let publish_channel = connection
        .create_channel()
        .await
        .context("Failed to allocation channel for message publishing")?;
    publish_channel
        .confirm_select(ConfirmSelectOptions { nowait: false })
        .await
        .context("Confirm select failed")?;
    let sign_context = SignContext {
        config,
        publish_channel,
        koji_signer,
        ostree_signer,
        coreos_signer,
    };
    consume(
        channel,
        queue.name().clone().to_string(),
        halt_token.clone(),
        sign_context,
    )
    .await?;

    Ok(())
}

#[derive(Clone)]
struct SignContext<K: KojiOps> {
    config: Arc<Config>,
    publish_channel: Channel,
    koji_signer: rpmsign::KojiSigner<K>,
    ostree_signer: crate::ostree::OstreeSigner,
    coreos_signer: coreos::CoreOsSigner,
}

async fn consume<K: KojiOps>(
    channel: Channel,
    queue_name: String,
    halt_token: CancellationToken,
    sign_context: SignContext<K>,
) -> anyhow::Result<()> {
    let consumer_options = BasicConsumeOptions::default();
    let mut consumer = channel
        .basic_consume(
            queue_name.into(),
            "siguldry-fedora-autopen".into(),
            consumer_options,
            FieldTable::default(),
        )
        .await
        .context("Failed to start basic consumer")?;
    let received_counter = crate::metrics_utils::messages_received();

    // Note that the channel's prefetch count will ensure this doesn't spawn a million tasks.
    let mut signing_tasks = tokio::task::JoinSet::new();
    loop {
        // Drain any completed tasks before selecting the next message or we'll leak memory
        drain_tasks(&mut signing_tasks);

        let message = tokio::select! {
            message = consumer.next() => {
                message
            }
            _ = tokio::time::sleep(Duration::from_secs(15)) => {
                // Restart the loop occassionally so the active tasks are drained and metrics are accurate.
                continue;
            }
            _ = halt_token.cancelled() => {
                tracing::info!(pending_tasks=signing_tasks.len(), "Consumer halting, waiting for pending tasks to complete");
                drain_tasks(&mut signing_tasks);

                if let Err(error) = channel.close(0, "Normal shutdown".into()).await {
                    tracing::error!(?error, "Failed to gracefully shut down the AMQP channel");
                }
                break;
            }
        };
        received_counter.increment(1);

        match message {
            Some(Ok(delivery)) => {
                signing_tasks.spawn(process_message(sign_context.clone(), delivery));
                crate::metrics_utils::messages_active().set(signing_tasks.len() as f64);
                tracing::debug!(
                    active_tasks = signing_tasks.len(),
                    "Dispatched new signing task"
                );
            }
            Some(Err(error)) => {
                tracing::warn!(
                    ?error,
                    "AMQP delivery error occurred; restarting connection..."
                );
                signing_tasks.abort_all();
                signing_tasks
                    .join_all()
                    .await
                    .into_iter()
                    .for_each(|result| {
                        if let Err(error) = result {
                            tracing::info!(
                                ?error,
                                "Signing task, cancelled due to a connection error, failed"
                            );
                        }
                    });

                return Err(anyhow::anyhow!("Halting consumer due to AMQP error"));
            }
            None => {
                tracing::info!(
                    pending_tasks = signing_tasks.len(),
                    "Consumer stream ended, waiting for pending tasks to complete"
                );
                signing_tasks
                    .join_all()
                    .await
                    .into_iter()
                    .for_each(|result| {
                        if let Err(error) = result {
                            tracing::error!(?error, "Signing task failed");
                        }
                    });
                break;
            }
        }
    }

    Ok(())
}

fn drain_tasks(signing_tasks: &mut JoinSet<anyhow::Result<()>>) {
    while let Some(task) = signing_tasks.try_join_next() {
        match task {
            Ok(Ok(())) => tracing::debug!(
                pending_tasks = signing_tasks.len(),
                "Signing task finished successfully"
            ),
            Ok(Err(error)) => tracing::warn!(?error, "The message could not be acknowledged"),
            Err(error) => {
                if error.is_panic() {
                    tracing::error!(?error, "The message was not processed because it panicked");
                } else if error.is_cancelled() {
                    tracing::info!("The task was cancelled");
                } else {
                    tracing::warn!(?error, "The task failed to join for unknown reasons");
                }
            }
        };
    }
    crate::metrics_utils::messages_active().set(signing_tasks.len() as f64);
}

#[instrument(skip_all, err(level =  Level::WARN), name = "message", fields(message_id = tracing::field::Empty))]
async fn process_message<K: KojiOps>(
    sign_context: SignContext<K>,
    delivery: Delivery,
) -> anyhow::Result<()> {
    let success_counter = crate::metrics_utils::messages_succeeded();
    let failed_counter = crate::metrics_utils::messages_failed();
    let dropped_counter = crate::metrics_utils::messages_dropped();

    let message_id = if let Some(message_id) =
        delivery.properties.message_id().as_ref().and_then(|id| {
            uuid::Uuid::parse_str(id.as_str())
                .inspect_err(|error| tracing::warn!(?error, "Failed to parse message ID"))
                .ok()
        }) {
        message_id
    } else {
        tracing::error!("Message didn't include a valid message ID!");
        delivery
            .nack(BasicNackOptions {
                multiple: false,
                requeue: false,
            })
            .await?;
        dropped_counter.increment(1);
        return Ok(());
    };
    tracing::Span::current().record("message_id", tracing::field::display(message_id));

    if let Some(content_type) = delivery.properties.content_type()
        && content_type.as_str() != "application/json"
    {
        tracing::error!(
            content_type = content_type.as_str(),
            "Message with unexpected content type, skipping!"
        );
        delivery
            .nack(BasicNackOptions {
                multiple: false,
                requeue: false,
            })
            .await?;
        dropped_counter.increment(1);
        return Ok(());
    }

    if let Some(content_encoding) = delivery.properties.content_encoding()
        && !content_encoding.as_str().eq_ignore_ascii_case("utf-8")
    {
        tracing::error!(
            content_encoding = content_encoding.as_str(),
            "Message with unexpected content encoding, skipping!"
        );
        delivery
            .nack(BasicNackOptions {
                multiple: false,
                requeue: false,
            })
            .await?;
        dropped_counter.increment(1);
        return Ok(());
    }

    let headers = if let Some(headers) = delivery.properties.headers() {
        tracing::trace!(?headers, "message headers found");
        headers
    } else {
        tracing::error!("Message didn't include any headers!");
        delivery
            .nack(BasicNackOptions {
                multiple: false,
                requeue: false,
            })
            .await?;
        dropped_counter.increment(1);
        return Ok(());
    };

    let schema = if let Some(AMQPValue::LongString(schema)) =
        headers.inner().get("fedora_messaging_schema")
    {
        schema.to_string()
    } else {
        tracing::error!(
            ?headers,
            "Message headers did not include 'fedora_messaging_schema'"
        );
        delivery
            .nack(BasicNackOptions {
                multiple: false,
                requeue: false,
            })
            .await?;
        dropped_counter.increment(1);
        return Ok(());
    };
    let topic = delivery.routing_key.as_str();
    tracing::info!(schema, topic, "New message delivered");

    // For messages we previously requeued, introduce a modest delay to avoid spinning as fast as we can
    if delivery.redelivered {
        let delay = Duration::from_secs(sign_context.config.amqp.redelivery_delay);
        tracing::info!(
            "Message has been previously delivered; delaying processing by {} seconds",
            delay.as_secs()
        );
        tokio::time::sleep(delay).await;
    }

    let result = match schema.as_str() {
        "koji_fedoramessaging.tag.TagV1" => {
            tracing::trace!("Processing Koji tag event");
            let tag_event: rpmsign::BuildsysTag = serde_json::from_slice(&delivery.data)
                .context("Message failed to deserialize to the expected schema")?;
            tokio::time::timeout(
                sign_context.config.rpm.timeout,
                sign_context.koji_signer.sign(tag_event),
            )
            .await
        }
        schema => {
            // Annoyingly, some of the messages don't have a schema
            match topic {
                topic if topic.ends_with(".pungi.compose.ostree") => {
                    let event: Result<ostree::OstreeCompose, _> =
                        serde_json::from_slice(&delivery.data);
                    let result = match event {
                        Ok(event) => sign_context.ostree_signer.sign(event).await,
                        Err(error) => {
                            tracing::error!(?error, "Message body is not valid; skipping");
                            Ok(())
                        }
                    };
                    Ok(result)
                }
                topic if topic.ends_with(".coreos.build.request.artifacts-sign") => {
                    let event: Result<coreos::ArtifactSign, _> =
                        serde_json::from_slice(&delivery.data);
                    let result = match event {
                        Ok(event) => {
                            let mut response_event = event.clone();
                            match sign_context.coreos_signer.sign(event).await.inspect_err(
                                |_err| crate::metrics_utils::coreos_failed().increment(1),
                            )? {
                                coreos::Status::Failure(reason) => {
                                    response_event.status = Some("FAILURE".to_string());
                                    response_event.failure_message = Some(reason);
                                }
                                coreos::Status::Success => {
                                    response_event.status = Some("SUCCESS".to_string());
                                }
                            };
                            let response_data = serde_json::to_vec(&response_event)
                                .context("Failed to serialize CoreOS AMQP response")?;

                            let publish_topic = format!("{topic}.finished").into();
                            let mut reply_headers = headers.clone();
                            let sent_at = time::UtcDateTime::now()
                                .format(&time::format_description::well_known::Rfc3339)
                                .context("Failed to format sent-at timestamp")?;
                            reply_headers
                                .insert("sent-at".into(), AMQPValue::LongString(sent_at.into()));

                            let properties = BasicProperties::default()
                                .with_content_type("application/json".into())
                                .with_content_encoding("utf-8".into())
                                .with_delivery_mode(2)
                                .with_message_id(uuid::Uuid::new_v4().to_string().into())
                                .with_headers(reply_headers)
                                .with_app_id("fedora-siguldry-autopen".into());

                            // Wrapped in a block to ensure the metrics are recorded properly
                            async {
                                let confirm = sign_context
                                    .publish_channel
                                    .basic_publish(
                                        "amq.topic".into(),
                                        publish_topic,
                                        BasicPublishOptions::default(),
                                        &response_data,
                                        properties,
                                    )
                                    .await
                                    .context("Failed to publish CoreOS finished message")?
                                    .await
                                    .context("Failed to receive publish confirmation response")?;
                                match confirm {
                                    lapin::Confirmation::Ack(None) => Ok(()),
                                    lapin::Confirmation::Ack(Some(return_message)) => {
                                        tracing::warn!(return_message.reply_code, ?return_message.reply_text, "AMQP broker acknowledge, but returned, the CoreOS publish message");
                                        Err(anyhow::anyhow!(
                                            "AMQP broker returned the CoreOS publish message"
                                        ))
                                    }
                                    lapin::Confirmation::Nack(return_message) => {
                                        let reply_code = return_message.as_ref().map(|m| m.reply_code);
                                        let reply_text = return_message.as_ref().map(|m| &m.reply_text);
                                        tracing::error!(
                                            ?reply_code,
                                            ?reply_text,
                                            "AMQP broker nacked the CoreOS publish message"
                                        );
                                        Err(anyhow::anyhow!(
                                            "AMQP broker returned the CoreOS publish message"
                                        ))
                                    }
                                    lapin::Confirmation::NotRequested => {
                                        tracing::error!(
                                            "Message confirmations are not enabled, this is not good"
                                        );
                                        Err(anyhow::anyhow!(
                                            "AMQP broker reported confirms were not requested! This is a bug!"
                                        ))
                                    }
                                }?;

                                if response_event.failure_message.is_none() {
                                    crate::metrics_utils::coreos_succeeded().increment(1);
                                } else {
                                    crate::metrics_utils::coreos_skipped().increment(1);
                                }
                                Ok::<_, anyhow::Error>(())
                            }.await.inspect_err(
                                |_err| crate::metrics_utils::coreos_failed().increment(1),
                            )?;

                            Ok(())
                        }
                        Err(error) => {
                            tracing::error!(?error, topic, "Message body is not valid; skipping");
                            Ok(())
                        }
                    };
                    Ok(result)
                }
                topic => {
                    tracing::error!(
                        schema,
                        topic,
                        "Message schema is unknown and no topic match exists; skipping"
                    );
                    Ok(Ok(()))
                }
            }
        }
    };
    match result {
        Ok(Ok(_)) => {
            delivery.ack(BasicAckOptions { multiple: false }).await?;
            success_counter.increment(1);
            tracing::info!("Message processed");
        }
        Ok(Err(error)) => {
            tracing::warn!(
                ?error,
                "Failed to process signing request, requeuing message for later attempt"
            );
            delivery
                .nack(BasicNackOptions {
                    multiple: false,
                    requeue: true,
                })
                .await?;
            failed_counter.increment(1);
        }
        Err(_elapsed) => {
            tracing::warn!("Signing request timed out, requeuing message for later attempt");
            delivery
                .nack(BasicNackOptions {
                    multiple: false,
                    requeue: true,
                })
                .await?;
            failed_counter.increment(1);
        }
    };

    Ok(())
}

#[instrument(skip_all)]
async fn connect(config: &crate::config::Amqp) -> anyhow::Result<Connection> {
    tracing::info!("Starting connection to the AMQP broker");
    let pem = std::fs::read_to_string(&config.tls.certfile)
        .with_context(|| {
            format!(
                "Unable to read client certificate {}",
                config.tls.certfile.display()
            )
        })?
        .into_bytes();
    let key = std::fs::read_to_string(&config.tls.keyfile)
        .with_context(|| {
            format!(
                "Unable to read client private key {}",
                config.tls.keyfile.display()
            )
        })?
        .into_bytes();
    let cert_chain = std::fs::read_to_string(&config.tls.ca_cert).with_context(|| {
        format!(
            "Unable to read certificate authority {}",
            config.tls.ca_cert.display()
        )
    })?;
    let identity = OwnedIdentity::PKCS8 { pem, key };
    let tls_config = OwnedTLSConfig {
        identity: Some(identity),
        cert_chain: Some(cert_chain),
    };
    let properties =
        ConnectionProperties::default().with_client_property("app".into(), "huh".into());
    let connection = lapin::ConnectionBuilder::new()
        .context("Failed to create connection builder")?
        .with_uri_str(config.amqp_url.clone())
        .with_tls_config(tls_config)
        .with_properties(properties)
        .connect()
        .await
        .context("Failed to connect to the AMQP server")?;
    tracing::info!("Connection established");

    Ok(connection)
}
