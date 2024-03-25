package org.dependencytrack.event.kafka.processor.api;

import org.apache.kafka.clients.consumer.ConsumerRecord;

import java.util.List;

interface ProcessingStrategy {

    /**
     * Process zero or more {@link ConsumerRecord}s.
     *
     * @param records The {@link ConsumerRecord}s to process
     */
    void processRecords(final List<ConsumerRecord<byte[], byte[]>> records);

}