package org.dependencytrack.event.kafka;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.notification.Notification;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.KafkaException;
import org.dependencytrack.event.ComponentMetricsUpdateEvent;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.event.kafka.dto.Component;
import org.dependencytrack.event.kafka.dto.VulnerabilityScanKey;
import org.dependencytrack.event.kafka.serialization.VulnerabilityScanKeySerializer;
import org.dependencytrack.notification.NotificationGroup;

import java.nio.charset.StandardCharsets;
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

    private final Producer<String, Object> producer;

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
    KafkaEventDispatcher(final Producer<String, Object> producer) {
        this.producer = producer;
    }

    /**
     * Dispatch a given {@link Event} to Kafka.
     * <p>
     * This call is blocking and will wait for the server to acknowledge the event.
     *
     * @param event The {@link Event} to dispatch
     * @return A {@link RecordMetadata} instance for the dispatched event
     * @throws IllegalArgumentException When dispatching the given {@link Event} to Kafka is not supported
     * @throws KafkaException           When dispatching failed
     */
    public RecordMetadata dispatch(final Event event) {
        if (event instanceof final ComponentVulnerabilityAnalysisEvent vaEvent) {
            final var component = new Component(vaEvent.component());
            final String scanKeySerialized;
            try (final var serializer = new VulnerabilityScanKeySerializer()) {
                final var scanKey = new VulnerabilityScanKey(vaEvent.token().toString(), component.uuid());
                scanKeySerialized = new String(serializer.serialize(null, scanKey), StandardCharsets.UTF_8);
            }
            return dispatchInternal(KafkaTopic.VULN_ANALYSIS_COMPONENT, scanKeySerialized, component,
                    Map.of("level", vaEvent.level().name()));
        } else if (event instanceof final ComponentRepositoryMetaAnalysisEvent rmaEvent) {
            final var component = new Component(rmaEvent.component());
            return dispatchInternal(KafkaTopic.REPO_META_ANALYSIS_COMPONENT, component.uuid().toString(), component, null);
        } else if (event instanceof final OsvMirrorEvent omEvent) {
            return dispatchInternal(KafkaTopic.MIRROR_OSV, omEvent.ecosystem(), "", null);
        } else if (event instanceof final NistMirrorEvent nmEvent) {
            return dispatchInternal(KafkaTopic.MIRROR_NVD, UUID.randomUUID().toString(), "", null);
        } else if(event instanceof  final ComponentMetricsUpdateEvent componentMetricsUpdateEvent){
            return dispatchInternal(KafkaTopic.COMPONENT_METRICS, componentMetricsUpdateEvent.uuid().toString(), componentMetricsUpdateEvent.dependencyMetrics(), null);
        }

        throw new IllegalArgumentException("Cannot publish event of type " + event.getClass().getName() + " to Kafka");
    }

    public RecordMetadata dispatchNotification(final Notification notification) {
        return switch (NotificationGroup.valueOf(notification.getGroup())) {
            case CONFIGURATION -> dispatchInternal(KafkaTopic.NOTIFICATION_CONFIGURATION, null, notification, null);
            case DATASOURCE_MIRRORING ->
                    dispatchInternal(KafkaTopic.NOTIFICATION_DATASOURCE_MIRRORING, null, notification, null);
            case REPOSITORY -> dispatchInternal(KafkaTopic.NOTIFICATION_REPOSITORY, null, notification, null);
            case INTEGRATION -> dispatchInternal(KafkaTopic.NOTIFICATION_INTEGRATION, null, notification, null);
            case ANALYZER -> dispatchInternal(KafkaTopic.NOTIFICATION_ANALYZER, null, notification, null);
            case BOM_CONSUMED -> dispatchInternal(KafkaTopic.NOTIFICATION_BOM_CONSUMED, null, notification, null);
            case BOM_PROCESSED -> dispatchInternal(KafkaTopic.NOTIFICATION_BOM_PROCESSED, null, notification, null);
            case FILE_SYSTEM -> dispatchInternal(KafkaTopic.NOTIFICATION_FILE_SYSTEM, null, notification, null);
            case INDEXING_SERVICE ->
                    dispatchInternal(KafkaTopic.NOTIFICATION_INDEXING_SERVICE, null, notification, null);
            case NEW_VULNERABILITY ->
                    dispatchInternal(KafkaTopic.NOTIFICATION_NEW_VULNERABILITY, null, notification, null);
            case NEW_VULNERABLE_DEPENDENCY ->
                    dispatchInternal(KafkaTopic.NOTIFICATION_NEW_VULNERABLE_DEPENDENCY, null, notification, null);
            case POLICY_VIOLATION ->
                    dispatchInternal(KafkaTopic.NOTIFICATION_POLICY_VIOLATION, null, notification, null);
            case PROJECT_AUDIT_CHANGE ->
                    dispatchInternal(KafkaTopic.NOTIFICATION_PROJECT_AUDIT_CHANGE, null, notification, null);
            case PROJECT_CREATED -> dispatchInternal(KafkaTopic.NOTIFICATION_PROJECT_CREATED, null, notification, null);
            case VEX_CONSUMED -> dispatchInternal(KafkaTopic.NOTIFICATION_VEX_CONSUMED, null, notification, null);
            case VEX_PROCESSED -> dispatchInternal(KafkaTopic.NOTIFICATION_VEX_PROCESSED, null, notification, null);
        };
    }


    private RecordMetadata dispatchInternal(final KafkaTopic topic, final String key, final Object value, final Map<String, String> headers) {
        try {
            final var record = new ProducerRecord<>(topic.getName(), key, value);
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
