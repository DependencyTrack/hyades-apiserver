package org.dependencytrack.event.kafka.processor.api;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.dependencytrack.event.kafka.processor.exception.RecordProcessingException;

import java.util.List;

/**
 * A processor of individual {@link ConsumerRecord}s, capable of producing zero or more {@link ProducerRecord}s.
 *
 * @param <CK> Type of the {@link ConsumerRecord} key
 * @param <CV> Type of the {@link ConsumerRecord} value
 * @param <PK> Type of the {@link ProducerRecord} key
 * @param <PV> Type of the {@link ProducerRecord} value
 */
public interface RecordProcessor<CK, CV, PK, PV> {

    /**
     * Process a {@link ConsumerRecord}, and produce zero or more {@link ProducerRecord}s.
     *
     * @param record The {@link ConsumerRecord} to process
     * @return Zero or more {@link ProducerRecord}s
     * @throws RecordProcessingException When processing the {@link ConsumerRecord} failed
     */
    List<ProducerRecord<PK, PV>> process(final ConsumerRecord<CK, CV> record) throws RecordProcessingException;

}
