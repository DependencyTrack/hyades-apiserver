package org.dependencytrack.event.kafka.processor;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.apache.kafka.common.record.TimestampType;
import org.dependencytrack.AbstractPostgresEnabledTest;

import java.time.Instant;
import java.util.Optional;

abstract class AbstractProcessorTest extends AbstractPostgresEnabledTest {

    <K, V> ConsumerRecord<K, V> createConsumerRecord(final K key, final V value) {
        return createConsumerRecord(key, value, Instant.now());
    }

    <K, V> ConsumerRecord<K, V> createConsumerRecord(final K key, final V value, final Instant timestamp) {
        return new ConsumerRecord<>("topic", 0, 1, timestamp.toEpochMilli(), TimestampType.CREATE_TIME, -1, -1,
                key, value, new RecordHeaders(), Optional.empty());
    }

}
