package org.dependencytrack.event.kafka;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.notification.Notification;
import org.apache.kafka.clients.producer.Callback;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.serialization.Serde;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.event.GitHubAdvisoryMirrorEvent;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.model.Vulnerability;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import static java.util.Objects.requireNonNullElseGet;

/**
 * An {@link Event} dispatcher that wraps a Kafka {@link Producer}.
 */
public class KafkaEventDispatcher {

    private static final Logger LOGGER = Logger.getLogger(KafkaEventDispatcher.class);

    private final Producer<byte[], byte[]> producer;

    public KafkaEventDispatcher() {
        this(KafkaProducerInitializer.getProducer());
    }

    /**
     * Constructor for unit tests.
     * <p>
     * The intention is to be able to provide {@link org.apache.kafka.clients.producer.MockProducer}
     * instances here for testing purposes.
     *
     * @param producer The {@link Producer} to use
     */
    KafkaEventDispatcher(final Producer<byte[], byte[]> producer) {
        this.producer = producer;
    }

    /**
     * Asynchronously dispatch a given {@link Event} to Kafka.
     *
     * @param event    The {@link Event} to dispatch
     * @param callback A {@link Callback} to execute once the record has been acknowledged by the broker,
     *                 or sending the record failed; When {@code null}, {@link KafkaDefaultProducerCallback}
     *                 will be used
     * @return A {@link Future} holding a {@link RecordMetadata} instance for the dispatched event,
     * or {@code null} when the event was not dispatched
     * @throws IllegalArgumentException When dispatching the given {@link Event} to Kafka is not supported
     * @see org.apache.kafka.clients.producer.KafkaProducer#send(ProducerRecord, Callback)
     */
    public Future<RecordMetadata> dispatchAsync(final Event event, final Callback callback) {
        if (event instanceof final ComponentVulnerabilityAnalysisEvent e) {
            return dispatchAsyncInternal(KafkaEventConverter.convert(e), callback);
        } else if (event instanceof final ComponentRepositoryMetaAnalysisEvent e) {
            LOGGER.debug("Dispatch internal called for component: " + e.purlCoordinates() + " Component is internal: " + e.internal());
            return dispatchAsyncInternal(KafkaEventConverter.convert(e), callback);
        } else if (event instanceof final OsvMirrorEvent e) {
            return dispatchAsyncInternal(new KafkaEvent<>(KafkaTopics.VULNERABILITY_MIRROR_COMMAND, Vulnerability.Source.OSV.name(), e.ecosystem(), null), callback);
        } else if (event instanceof NistMirrorEvent) {
            return dispatchAsyncInternal(new KafkaEvent<>(KafkaTopics.VULNERABILITY_MIRROR_COMMAND, Vulnerability.Source.NVD.name(), "", null), callback);
        } else if (event instanceof GitHubAdvisoryMirrorEvent) {
            return dispatchAsyncInternal(new KafkaEvent<>(KafkaTopics.VULNERABILITY_MIRROR_COMMAND, Vulnerability.Source.GITHUB.name(), "", null), callback);
        } else if (event instanceof EpssMirrorEvent) {
            return dispatchAsyncInternal(new KafkaEvent<>(KafkaTopics.VULNERABILITY_MIRROR_COMMAND, "EPSS", "", null), callback);
        }

        throw new IllegalArgumentException("Cannot publish event of type " + event.getClass().getName() + " to Kafka");
    }

    /**
     * Asynchronously dispatch a given {@link Event} to Kafka.
     *
     * @param event The {@link Event} to dispatch
     * @return A {@link Future} holding a {@link RecordMetadata} instance for the dispatched event,
     * or {@code null} when the event was not dispatched
     * @see #dispatchAsync(Event, Callback)
     */
    public Future<RecordMetadata> dispatchAsync(final Event event) {
        return dispatchAsync(event, null);
    }

    /**
     * Dispatch a given {@link Event} to Kafka, and wait for the broker to acknowledge it.
     * <p>
     * Should only be used when successful delivery must be guaranteed, as it will have a
     * negative impact on the producer's internal batching mechanism.
     *
     * @param event The {@link Event} to dispatch
     * @return A {@link RecordMetadata} instance for the dispatched event, or {@code null} when the event was not dispatched
     */
    public RecordMetadata dispatchBlocking(final Event event) {
        try {
            return dispatchAsync(event, null).get();
        } catch (ExecutionException | InterruptedException e) {
            throw new KafkaException(e);
        }
    }

    /**
     * Asynchronously dispatch a given {@link Notification} to Kafka.
     *
     * @param alpineNotification The {@link Notification} to dispatch
     * @return A {@link Future} holding a {@link RecordMetadata} instance for the dispatched notification,
     * or {@code null} when the event was not dispatched
     * @see org.apache.kafka.clients.producer.KafkaProducer#send(ProducerRecord)
     */
    public Future<RecordMetadata> dispatchAsync(final UUID projectUuid, final Notification alpineNotification) {
        return dispatchAsyncInternal(KafkaEventConverter.convert(projectUuid, alpineNotification), null);
    }

    /**
     * Asynchronously dispatch a given {@link org.dependencytrack.proto.notification.v1.Notification} to Kafka.
     *
     * @param key          The event key to use
     * @param notification The {@link org.dependencytrack.proto.notification.v1.Notification} to dispatch
     * @return A {@link Future} holding a {@link RecordMetadata} instance for the dispatched notification,
     * or {@code null} when the event was not dispatched
     */
    public Future<RecordMetadata> dispatchAsync(final String key, final org.dependencytrack.proto.notification.v1.Notification notification) {
        return dispatchAsyncInternal(KafkaEventConverter.convert(key, notification), null);
    }

    private <K, V> Future<RecordMetadata> dispatchAsyncInternal(final KafkaEvent<K, V> event, final Callback callback) {
        if (event == null) {
            if (callback != null) {
                // Callers are expecting that their callback will be executed,
                // no matter if sending the record failed or succeeded.
                callback.onCompletion(null, null);
            }

            return CompletableFuture.completedFuture(null);
        }

        final byte[] keyBytes;
        try (final Serde<K> keySerde = event.topic().keySerde()) {
            keyBytes = keySerde.serializer().serialize(event.topic().name(), event.key());
        } catch (SerializationException e) {
            throw new KafkaException("Failed to serialize key", e);
        }

        final byte[] valueBytes;
        try (final Serde<V> valueSerde = event.topic().valueSerde()) {
            valueBytes = valueSerde.serializer().serialize(event.topic().name(), event.value());
        } catch (SerializationException e) {
            throw new KafkaException("Failed to serialize value", e);
        }

        final var record = new ProducerRecord<>(event.topic().name(), keyBytes, valueBytes);
        if (event.headers() != null) {
            for (final Map.Entry<String, String> header : event.headers().entrySet()) {
                record.headers().add(header.getKey(), header.getValue().getBytes(StandardCharsets.UTF_8));
            }
        }

        return producer.send(record, requireNonNullElseGet(callback,
                () -> new KafkaDefaultProducerCallback(LOGGER, record.topic(), event.key())));
    }

}
