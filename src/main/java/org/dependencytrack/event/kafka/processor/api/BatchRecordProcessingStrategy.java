package org.dependencytrack.event.kafka.processor.api;

import alpine.common.logging.Logger;
import io.confluent.parallelconsumer.PCRetriableException;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.serialization.Serde;
import org.dependencytrack.event.kafka.processor.exception.RecordProcessingException;
import org.dependencytrack.event.kafka.processor.exception.RetryableRecordProcessingException;

import java.util.ArrayList;
import java.util.List;

/**
 * A {@link RecordProcessingStrategy} that processes records in batches.
 *
 * @param <K> Type of the {@link ConsumerRecord} key
 * @param <V> Type of the {@link ConsumerRecord} value
 */
class BatchRecordProcessingStrategy<K, V> extends AbstractRecordProcessingStrategy<K, V> {

    private static final Logger LOGGER = Logger.getLogger(BatchRecordProcessingStrategy.class);

    private final BatchRecordProcessor<K, V> batchConsumer;

    BatchRecordProcessingStrategy(final BatchRecordProcessor<K, V> batchConsumer,
                                  final Serde<K> keySerde, final Serde<V> valueSerde) {
        super(keySerde, valueSerde);
        this.batchConsumer = batchConsumer;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void processRecords(final List<ConsumerRecord<byte[], byte[]>> records) {
        final var deserializedRecords = new ArrayList<ConsumerRecord<K, V>>(records.size());
        for (final ConsumerRecord<byte[], byte[]> record : records) {
            try {
                deserializedRecords.add(deserialize(record));
            } catch (SerializationException e) {
                // TODO: Consider supporting error handlers, e.g. to send record to DLT.
                LOGGER.error("Failed to deserialize consumer record %s; Skipping".formatted(record), e);
            }
        }

        if (deserializedRecords.isEmpty()) {
            LOGGER.warn("All of the %d records in this batch failed to be deserialized".formatted(records.size()));
            return;
        }

        try {
            batchConsumer.process(deserializedRecords);
        } catch (RetryableRecordProcessingException e) {
            LOGGER.warn("Encountered retryable exception while processing %d records".formatted(deserializedRecords.size()), e);
            throw new PCRetriableException(e);
        } catch (RecordProcessingException | RuntimeException e) {
            LOGGER.error("Encountered non-retryable exception while processing %d records; Skipping".formatted(deserializedRecords.size()), e);
            // TODO: Consider supporting error handlers, e.g. to send records to DLT.
            // Skip records to avoid poison-pill scenario.
        }
    }

}
