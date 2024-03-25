/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.event.kafka.processor.api;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.serialization.Serde;
import org.datanucleus.api.jdo.exceptions.ConnectionInUseException;
import org.datanucleus.store.query.QueryInterruptedException;
import org.dependencytrack.event.kafka.processor.exception.RetryableProcessingException;
import org.postgresql.util.PSQLState;

import javax.jdo.JDOOptimisticVerificationException;
import java.net.SocketTimeoutException;
import java.sql.SQLException;
import java.sql.SQLTransientConnectionException;
import java.sql.SQLTransientException;
import java.util.List;
import java.util.concurrent.TimeoutException;

/**
 * An abstract {@link ProcessingStrategy} that provides various shared functionality.
 *
 * @param <K> Type of the {@link ConsumerRecord} key
 * @param <V> Type of the {@link ConsumerRecord} value
 */
abstract class AbstractProcessingStrategy<K, V> implements ProcessingStrategy {

    private final Serde<K> keySerde;
    private final Serde<V> valueSerde;

    AbstractProcessingStrategy(final Serde<K> keySerde, final Serde<V> valueSerde) {
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

    private static final List<Class<? extends Exception>> KNOWN_TRANSIENT_EXCEPTIONS = List.of(
            ConnectTimeoutException.class,
            ConnectionInUseException.class,
            JDOOptimisticVerificationException.class,
            QueryInterruptedException.class,
            SocketTimeoutException.class,
            SQLTransientException.class,
            SQLTransientConnectionException.class,
            TimeoutException.class
    );

    boolean isRetryableException(final Throwable throwable) {
        if (throwable instanceof RetryableProcessingException) {
            return true;
        }

        final boolean isKnownTransientException = ExceptionUtils.getThrowableList(throwable).stream()
                .anyMatch(cause -> KNOWN_TRANSIENT_EXCEPTIONS.contains(cause.getClass()));
        if (isKnownTransientException) {
            return true;
        }

        return ExceptionUtils.getRootCause(throwable) instanceof final SQLException se
               && PSQLState.isConnectionError(se.getSQLState());
    }

}
