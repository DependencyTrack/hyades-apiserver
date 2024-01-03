package org.dependencytrack.event.kafka.processor;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.apache.kafka.common.record.TimestampType;
import org.dependencytrack.AbstractPostgresEnabledTest;

import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNullElseGet;

abstract class AbstractProcessorTest extends AbstractPostgresEnabledTest {

    static <K, V> ConsumerRecordBuilder<K, V> aConsumerRecord(final K key, final V value) {
        return new ConsumerRecordBuilder<>(key, value);
    }

    static final class ConsumerRecordBuilder<K, V> {

        private final K key;
        private final V value;
        private Instant timestamp;
        private Headers headers;

        private ConsumerRecordBuilder(final K key, final V value) {
            this.key = key;
            this.value = value;
        }

        ConsumerRecordBuilder<K, V> withTimestamp(final Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        ConsumerRecordBuilder<K, V> withHeaders(final Headers headers) {
            this.headers = headers;
            return this;
        }

        ConsumerRecord<K, V> build() {
            final Instant timestamp = requireNonNullElseGet(this.timestamp, Instant::now);
            final Headers headers = requireNonNullElseGet(this.headers, RecordHeaders::new);
            return new ConsumerRecord<>(
                    "topicName",
                    /* partition */ 0,
                    /* offset */ 1,
                    timestamp.toEpochMilli(), TimestampType.CREATE_TIME,
                    /* serializedKeySize */ -1,
                    /* serializedValueSize */ -1,
                    this.key, this.value,
                    headers,
                    /* leaderEpoch */ Optional.empty());
        }

    }

}
