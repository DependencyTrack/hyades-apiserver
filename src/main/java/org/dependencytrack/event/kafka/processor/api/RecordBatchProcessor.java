package org.dependencytrack.event.kafka.processor.api;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.dependencytrack.event.kafka.processor.exception.RecordProcessingException;

import java.util.List;

/**
 * A processor of {@link ConsumerRecord} batches, capable of producing zero or more {@link ProducerRecord}s.
 *
 * @param <CK> Type of the {@link ConsumerRecord} key
 * @param <CV> Type of the {@link ConsumerRecord} value
 * @param <PK> Type of the {@link ProducerRecord} key
 * @param <PV> Type of the {@link ProducerRecord} value
 */
public interface RecordBatchProcessor<CK, CV, PK, PV> {

    /**
     * Process a batch of {@link ConsumerRecord}s, and produce zero or more {@link ProducerRecord}s.
     *
     * @param records Batch of {@link ConsumerRecord}s to process
     * @return Zero or more {@link ProducerRecord}s
     * @throws RecordProcessingException When processing the batch of {@link ConsumerRecord}s failed
     */
    List<ProducerRecord<PK, PV>> process(final List<ConsumerRecord<CK, CV>> records) throws RecordProcessingException;

}
