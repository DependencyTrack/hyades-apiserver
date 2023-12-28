package org.dependencytrack.event.kafka.processor.api;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.dependencytrack.event.kafka.processor.exception.RecordProcessingException;

import java.util.List;

/**
 * A processor of {@link ConsumerRecord} batches.
 *
 * @param <K> Type of the {@link ConsumerRecord} key
 * @param <V> Type of the {@link ConsumerRecord} value
 */
public interface BatchRecordProcessor<K, V> {

    /**
     * Process a batch of {@link ConsumerRecord}s.
     *
     * @param records Batch of {@link ConsumerRecord}s to process
     * @throws RecordProcessingException When consuming the batch of {@link ConsumerRecord}s failed
     */
    void process(final List<ConsumerRecord<K, V>> records) throws RecordProcessingException;

}
