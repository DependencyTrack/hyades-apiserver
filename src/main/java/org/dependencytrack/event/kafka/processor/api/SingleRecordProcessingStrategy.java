package org.dependencytrack.event.kafka.processor.api;

import alpine.common.logging.Logger;
import io.confluent.parallelconsumer.PCRetriableException;
import io.confluent.parallelconsumer.PollContext;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.serialization.Serde;
import org.dependencytrack.event.kafka.processor.exception.RecordProcessingException;
import org.dependencytrack.event.kafka.processor.exception.RetryableRecordProcessingException;

/**
 * A {@link RecordProcessingStrategy} that processes records individually.
 *
 * @param <K> Type of the {@link ConsumerRecord} key
 * @param <V> Type of the {@link ConsumerRecord} value
 */
class SingleRecordProcessingStrategy<K, V> extends AbstractRecordProcessingStrategy<K, V> {

    private static final Logger LOGGER = Logger.getLogger(SingleRecordProcessingStrategy.class);

    private final SingleRecordProcessor<K, V> recordProcessor;

    SingleRecordProcessingStrategy(final SingleRecordProcessor<K, V> recordProcessor,
                                   final Serde<K> keySerde, final Serde<V> valueSerde) {
        super(keySerde, valueSerde);
        this.recordProcessor = recordProcessor;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void handlePoll(final PollContext<byte[], byte[]> pollCtx) {
        final ConsumerRecord<byte[], byte[]> record = pollCtx.getSingleConsumerRecord();

        final ConsumerRecord<K, V> deserializedRecord;
        try {
            deserializedRecord = deserialize(record);
        } catch (SerializationException e) {
            LOGGER.error("Failed to deserialize consumer record %s; Skipping".formatted(record), e);
            // TODO: Consider supporting error handlers, e.g. to send record to DLT.
            return; // Skip record to avoid poison-pill scenario.
        }

        try {
            recordProcessor.process(deserializedRecord);
        } catch (RetryableRecordProcessingException e) {
            LOGGER.warn("Encountered retryable exception while processing %s".formatted(deserializedRecord), e);
            throw new PCRetriableException(e);
        } catch (RecordProcessingException | RuntimeException e) {
            LOGGER.error("Encountered non-retryable exception while processing %s; Skipping".formatted(deserializedRecord), e);
            // TODO: Consider supporting error handlers, e.g. to send record to DLT.
            // Skip record to avoid poison-pill scenario.
        }
    }

}
