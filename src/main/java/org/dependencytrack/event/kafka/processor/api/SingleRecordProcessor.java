package org.dependencytrack.event.kafka.processor.api;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.dependencytrack.event.kafka.processor.exception.RecordProcessingException;

/**
 * A processor of individual {@link ConsumerRecord}s.
 *
 * @param <K> Type of the {@link ConsumerRecord} key
 * @param <V> Type of the {@link ConsumerRecord} value
 */
public interface SingleRecordProcessor<K, V> {

    /**
     * Process a {@link ConsumerRecord}.
     *
     * @param record The {@link ConsumerRecord} to process
     * @throws RecordProcessingException When processing the {@link ConsumerRecord} failed
     */
    void process(final ConsumerRecord<K, V> record) throws RecordProcessingException;

}
