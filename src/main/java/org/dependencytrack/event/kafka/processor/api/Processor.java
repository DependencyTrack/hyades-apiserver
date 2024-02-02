package org.dependencytrack.event.kafka.processor.api;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.dependencytrack.event.kafka.processor.exception.ProcessingException;

/**
 * A processor of individual {@link ConsumerRecord}s.
 *
 * @param <K> Type of the {@link ConsumerRecord} key
 * @param <V> Type of the {@link ConsumerRecord} value
 */
public interface Processor<K, V> {

    /**
     * Process a {@link ConsumerRecord}.
     * <p>
     * This method may be called by multiple threads concurrently and thus MUST be thread safe!
     *
     * @param record The {@link ConsumerRecord} to process
     * @throws ProcessingException When processing the {@link ConsumerRecord} failed
     */
    void process(final ConsumerRecord<K, V> record) throws ProcessingException;

}
