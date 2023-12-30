package org.dependencytrack.event.kafka;

import alpine.common.logging.Logger;
import org.apache.kafka.clients.producer.Callback;
import org.apache.kafka.clients.producer.RecordMetadata;

/**
 * A Kafka producer {@link Callback} that simply logs any errors.
 * <p>
 * It is used by {@link KafkaEventDispatcher} when no other {@link Callback} is provided.
 */
class KafkaDefaultProducerCallback implements Callback {

    private final Logger logger;
    private final String topic;
    private final Object key;

    KafkaDefaultProducerCallback(final Logger logger) {
        this(logger, null, null);
    }

    KafkaDefaultProducerCallback(final Logger logger, final String topic, final Object key) {
        this.logger = logger;
        this.topic = topic;
        this.key = key;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void onCompletion(final RecordMetadata metadata, final Exception exception) {
        if (exception != null) {
            if (topic != null) {
                logger.error("Failed to produce record with key %s to topic %s".formatted(key, topic), exception);
            } else {
                logger.error("Failed to produce record", exception);
            }
        }
    }

}
