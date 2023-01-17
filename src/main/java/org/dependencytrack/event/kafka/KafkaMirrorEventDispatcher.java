package org.dependencytrack.event.kafka;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.notification.Notification;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.KafkaException;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.kafka.dto.Component;
import org.dependencytrack.notification.NotificationGroup;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

/**
 * An {@link Event} dispatcher that wraps a Kafka {@link Producer}.
 */
public class KafkaMirrorEventDispatcher {

    private static final Logger LOGGER = Logger.getLogger(KafkaMirrorEventDispatcher.class);

    private final Producer<String, Object> producer;

    public KafkaMirrorEventDispatcher() {
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
    KafkaMirrorEventDispatcher(final Producer<String, Object> producer) {
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


    public RecordMetadata dispatch(String ecosystem){
        return dispatchInternal(KafkaTopic.MIRROR_OSV, ecosystem, "", null);
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
