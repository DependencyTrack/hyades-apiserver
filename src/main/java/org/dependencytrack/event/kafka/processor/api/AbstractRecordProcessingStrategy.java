package org.dependencytrack.event.kafka.processor.api;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.serialization.Serde;
import org.datanucleus.api.jdo.exceptions.ConnectionInUseException;
import org.datanucleus.store.query.QueryInterruptedException;
import org.dependencytrack.event.kafka.processor.exception.RetryableRecordProcessingException;

import javax.jdo.JDOOptimisticVerificationException;
import java.net.SocketTimeoutException;
import java.sql.SQLTransientException;
import java.util.concurrent.TimeoutException;

/**
 * An abstract {@link RecordProcessingStrategy} that provides various shared functionality.
 *
 * @param <K> Type of the {@link ConsumerRecord} key
 * @param <V> Type of the {@link ConsumerRecord} value
 */
abstract class AbstractRecordProcessingStrategy<K, V> implements RecordProcessingStrategy {

    private final Serde<K> keySerde;
    private final Serde<V> valueSerde;

    AbstractRecordProcessingStrategy(final Serde<K> keySerde, final Serde<V> valueSerde) {
        this.keySerde = keySerde;
        this.valueSerde = valueSerde;
    }

    /**
     * @param record The {@link ConsumerRecord} to deserialize key and value of
     * @return A {@link ConsumerRecord} with deserialized key and value
     * @throws SerializationException When deserializing the {@link ConsumerRecord} failed
     */
    ConsumerRecord<K, V> deserialize(final ConsumerRecord<byte[], byte[]> record) {
        final K deserializedKey;
        final V deserializedValue;
        try {
            deserializedKey = keySerde.deserializer().deserialize(record.topic(), record.key());
            deserializedValue = valueSerde.deserializer().deserialize(record.topic(), record.value());
        } catch (RuntimeException e) {
            if (e instanceof SerializationException) {
                throw e;
            }

            throw new SerializationException(e);
        }

        return new ConsumerRecord<>(record.topic(), record.partition(), record.offset(),
                record.timestamp(), record.timestampType(), record.serializedKeySize(), record.serializedValueSize(),
                deserializedKey, deserializedValue, record.headers(), record.leaderEpoch());
    }

    boolean isRetryableException(final Throwable throwable) {
        if (throwable instanceof RetryableRecordProcessingException) {
            return true;
        }

        final Throwable rootCause = ExceptionUtils.getRootCause(throwable);
        return rootCause instanceof TimeoutException
                || rootCause instanceof ConnectTimeoutException
                || rootCause instanceof SocketTimeoutException
                || rootCause instanceof ConnectionInUseException
                || rootCause instanceof QueryInterruptedException
                || rootCause instanceof JDOOptimisticVerificationException
                || rootCause instanceof SQLTransientException;
    }

}