package org.dependencytrack.event.kafka.processor.api;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.dependencytrack.event.kafka.processor.exception.RecordProcessingException;

import java.util.List;

/**
 * A specialized {@link RecordBatchProcessor} that only consumes records, but does not produce any.
 *
 * @param <K> Type of the {@link ConsumerRecord} key
 * @param <V> Type of the {@link ConsumerRecord} value
 */
public interface RecordBatchConsumer<K, V> extends RecordBatchProcessor<K, V, Void, Void> {

    /**
     * Consume a batch of {@link ConsumerRecord}s.
     *
     * @param records Batch of {@link ConsumerRecord}s to process
     * @throws RecordProcessingException When consuming the batch of {@link ConsumerRecord}s failed
     */
    void consume(final List<ConsumerRecord<K, V>> records) throws RecordProcessingException;

    /**
     * {@inheritDoc}
     */
    @Override
    default List<ProducerRecord<Void, Void>> process(final List<ConsumerRecord<K, V>> records) throws RecordProcessingException {
        consume(records);
        return null;
    }

}
