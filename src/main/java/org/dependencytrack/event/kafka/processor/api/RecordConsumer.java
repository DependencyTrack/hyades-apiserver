package org.dependencytrack.event.kafka.processor.api;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.dependencytrack.event.kafka.processor.exception.RecordProcessingException;

import java.util.List;

/**
 * A specialized {@link RecordProcessor} that only consumes records, but does not produce any.
 *
 * @param <K> Type of the {@link ConsumerRecord} key
 * @param <V> Type of the {@link ConsumerRecord} value
 */
public interface RecordConsumer<K, V> extends RecordProcessor<K, V, Void, Void> {

    /**
     * Consume a {@link ConsumerRecord}.
     *
     * @param record The {@link ConsumerRecord} to process
     * @throws RecordProcessingException When processing the {@link ConsumerRecord} failed
     */
    void consume(final ConsumerRecord<K, V> record) throws RecordProcessingException;

    /**
     * {@inheritDoc}
     */
    @Override
    default List<ProducerRecord<Void, Void>> process(final ConsumerRecord<K, V> record) throws RecordProcessingException {
        consume(record);
        return null;
    }

}
