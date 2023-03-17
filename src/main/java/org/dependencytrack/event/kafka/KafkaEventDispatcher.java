package org.dependencytrack.event.kafka;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.notification.Notification;
import com.github.packageurl.PackageURL;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.errors.SerializationException;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.notification.NotificationGroup;
import org.hyades.proto.vulnanalysis.v1.ScanCommand;
import org.hyades.proto.vulnanalysis.v1.ScanKey;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

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
     * Dispatch a given {@link Event} to Kafka.
     * <p>
     * This call is blocking and will wait for the server to acknowledge the event.
     *
     * @param event The {@link Event} to dispatch
     * @return A {@link RecordMetadata} instance for the dispatched event, or {@code null} when the event was not dispatched
     * @throws IllegalArgumentException When dispatching the given {@link Event} to Kafka is not supported
     * @throws KafkaException           When dispatching failed
     */
    public RecordMetadata dispatch(final Event event) {
        if (event instanceof final ComponentVulnerabilityAnalysisEvent vaEvent) {
            final var componentBuilder = org.hyades.proto.vulnanalysis.v1.Component.newBuilder()
                    .setUuid(vaEvent.component().getUuid().toString())
                    .setInternal(vaEvent.component().isInternal());
            Optional.ofNullable(vaEvent.component().getCpe()).ifPresent(componentBuilder::setCpe);
            Optional.ofNullable(vaEvent.component().getPurl()).map(PackageURL::canonicalize).ifPresent(componentBuilder::setPurl);
            Optional.ofNullable(vaEvent.component().getSwidTagId()).ifPresent(componentBuilder::setSwidTagId);

            return dispatchInternal(
                    KafkaTopics.VULN_ANALYSIS_COMMAND,
                    ScanKey.newBuilder()
                            .setScanToken(vaEvent.token().toString())
                            .setComponentUuid(vaEvent.component().getUuid().toString())
                            .build(),
                    ScanCommand.newBuilder()
                            .setComponent(componentBuilder)
                            .build(),
                    Map.of(KafkaEventHeaders.VULN_ANALYSIS_LEVEL, vaEvent.level().name())
            );
        } else if (event instanceof final ComponentRepositoryMetaAnalysisEvent rmaEvent) {
            if (rmaEvent.component() == null || rmaEvent.component().getPurl() == null) {
                return null;
            }

            return dispatchInternal(KafkaTopics.REPO_META_ANALYSIS_COMMAND,
                    rmaEvent.component().getPurl().canonicalize(),
                    org.hyades.proto.repometaanalysis.v1.AnalysisCommand.newBuilder()
                            .setComponent(org.hyades.proto.repometaanalysis.v1.Component.newBuilder()
                                    .setPurl(rmaEvent.component().getPurl().canonicalize())
                                    .setInternal(rmaEvent.component().isInternal()))
                            .build(),
                    null);
        } else if (event instanceof final OsvMirrorEvent omEvent) {
            return dispatchInternal(KafkaTopics.MIRROR_OSV, omEvent.ecosystem(), "", null);
        } else if (event instanceof NistMirrorEvent) {
            return dispatchInternal(KafkaTopics.MIRROR_NVD, UUID.randomUUID().toString(), "", null);
        }
        throw new IllegalArgumentException("Cannot publish event of type " + event.getClass().getName() + " to Kafka");
    }

    public RecordMetadata dispatchNotification(final Notification notification) {
        return switch (NotificationGroup.valueOf(notification.getGroup())) {
            case CONFIGURATION -> dispatchInternal(KafkaTopics.NOTIFICATION_CONFIGURATION, null, notification, null);
            case DATASOURCE_MIRRORING ->
                    dispatchInternal(KafkaTopics.NOTIFICATION_DATASOURCE_MIRRORING, null, notification, null);
            case REPOSITORY -> dispatchInternal(KafkaTopics.NOTIFICATION_REPOSITORY, null, notification, null);
            case INTEGRATION -> dispatchInternal(KafkaTopics.NOTIFICATION_INTEGRATION, null, notification, null);
            case ANALYZER -> dispatchInternal(KafkaTopics.NOTIFICATION_ANALYZER, null, notification, null);
            case BOM_CONSUMED -> dispatchInternal(KafkaTopics.NOTIFICATION_BOM_CONSUMED, null, notification, null);
            case BOM_PROCESSED -> dispatchInternal(KafkaTopics.NOTIFICATION_BOM_PROCESSED, null, notification, null);
            case FILE_SYSTEM -> dispatchInternal(KafkaTopics.NOTIFICATION_FILE_SYSTEM, null, notification, null);
            case INDEXING_SERVICE ->
                    dispatchInternal(KafkaTopics.NOTIFICATION_INDEXING_SERVICE, null, notification, null);
            case NEW_VULNERABILITY ->
                    dispatchInternal(KafkaTopics.NOTIFICATION_NEW_VULNERABILITY, null, notification, null);
            case NEW_VULNERABLE_DEPENDENCY ->
                    dispatchInternal(KafkaTopics.NOTIFICATION_NEW_VULNERABLE_DEPENDENCY, null, notification, null);
            case POLICY_VIOLATION ->
                    dispatchInternal(KafkaTopics.NOTIFICATION_POLICY_VIOLATION, null, notification, null);
            case PROJECT_AUDIT_CHANGE ->
                    dispatchInternal(KafkaTopics.NOTIFICATION_PROJECT_AUDIT_CHANGE, null, notification, null);
            case PROJECT_CREATED ->
                    dispatchInternal(KafkaTopics.NOTIFICATION_PROJECT_CREATED, null, notification, null);
            case VEX_CONSUMED -> dispatchInternal(KafkaTopics.NOTIFICATION_VEX_CONSUMED, null, notification, null);
            case VEX_PROCESSED -> dispatchInternal(KafkaTopics.NOTIFICATION_VEX_PROCESSED, null, notification, null);
        };
    }


    private <K, V> RecordMetadata dispatchInternal(final KafkaTopics.Topic<K, V> topic, final K key, final V value, final Map<String, String> headers) {
        final byte[] keyBytes;
        try {
            keyBytes = topic.keySerde().serializer().serialize(topic.name(), key);
        } catch (SerializationException e) {
            throw new KafkaException(e);
        }

        final byte[] valueBytes;
        try {
            valueBytes = topic.valueSerde().serializer().serialize(topic.name(), value);
        } catch (SerializationException e) {
            throw new KafkaException(e);
        }

        try {
            final var record = new ProducerRecord<>(topic.name(), keyBytes, valueBytes);
            Optional.ofNullable(headers)
                    .orElseGet(Collections::emptyMap)
                    .forEach((k, v) -> record.headers().add(k, v.getBytes()));
            final RecordMetadata recordMeta = producer.send(record).get();
            LOGGER.debug("Dispatched event (Topic: " + recordMeta.topic() + ", Partition: " + recordMeta.partition() + ", Offset: " + recordMeta.offset() + ")");
            return recordMeta;
        } catch (ExecutionException | InterruptedException e) {
            throw new KafkaException(e);
        }
    }

}
