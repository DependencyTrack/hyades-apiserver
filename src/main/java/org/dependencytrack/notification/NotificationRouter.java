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
package org.dependencytrack.notification;

import com.google.protobuf.DebugFormat;
import com.google.protobuf.InvalidProtocolBufferException;
import org.dependencytrack.proto.notification.v1.Notification;
import org.postgresql.PGConnection;
import org.postgresql.replication.LogSequenceNumber;
import org.postgresql.replication.PGReplicationStream;
import org.postgresql.util.PSQLException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.io.Closeable;
import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class NotificationRouter implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationRouter.class);
    private static final String PUBLICATION_NAME = "notification";
    private static final String REPLICATION_SLOT_NAME = "notification";

    private final DataSource dataSource;
    private ExecutorService executor;
    private volatile boolean stopping = false;

    public NotificationRouter(final DataSource dataSource) {
        this.dataSource = dataSource;
    }

    void start() {
        try (final Connection connection = dataSource.getConnection()) {
            ensurePublication(connection);
            ensureReplicationSlot(connection);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }

        stopping = false;
        executor = Executors.newSingleThreadExecutor();
        executor.execute(() -> {
            try (final Connection connection = dataSource.getConnection();
                 final PGReplicationStream replicationStream = startReplicationStream(connection)) {
                while (!stopping) {
                    final ByteBuffer messageBuffer = replicationStream.readPending();
                    if (messageBuffer == null) {
                        TimeUnit.MILLISECONDS.sleep(1000);
                        continue;
                    }

                    // TODO: Consume a batch, route them, then "commit"?
                    //  Doing this one-by-one could prove a tad inefficient.
                    final Optional<LogicalDecodingMessage> decodedMessage = decode(messageBuffer);

                    decodedMessage.ifPresent(this::process);

                    replicationStream.setAppliedLSN(replicationStream.getLastReceiveLSN());
                    replicationStream.setFlushedLSN(replicationStream.getLastReceiveLSN());
                }

                replicationStream.forceUpdateStatus();
            } catch (final SQLException | InterruptedException e) {
                // TODO: When another instance is already consuming from this slot,
                //  we get: `replication slot "notification" is active for PID XX`.
                //  Add a retry for that case, so another instance can resume the slot
                //  when the current consumer is stopped.
                LOGGER.error("Unable to start replication stream", e);
            }
        });
    }

    @Override
    public void close() {
        stopping = true;
        if (executor != null) {
            executor.close();
        }
    }

    private void process(final LogicalDecodingMessage message) {
        if (!"notification".equals(message.prefix())) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Skipping message with prefix {}", message.prefix());
            }

            return;
        }

        final Notification notification;
        try {
            notification = Notification.parseFrom(message.content());
        } catch (InvalidProtocolBufferException e) {
            LOGGER.warn("Failed to parse notification", e);
            return;
        }

        LOGGER.debug("Received notification: [{}]", DebugFormat.singleLine().lazyToString(notification));

        // TODO: Evaluate notification rules, schedule workflow for dispatch.
    }

    private Optional<LogicalDecodingMessage> decode(final ByteBuffer messageBuffer) {
        final var messageType = (char) messageBuffer.get();
        if (messageType != 'M') {
            if (messageType != /* BEGIN */ 'B' && messageType != /* COMMIT */ 'C') {
                LOGGER.warn("Unexpected message type: {}", messageType);
            } else if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Skipping message of type {}", messageType);
            }

            return Optional.empty();
        }

        return Optional.of(LogicalDecodingMessage.parse(messageBuffer));
    }

    private record LogicalDecodingMessage(
            boolean isTransactional,
            LogSequenceNumber lsn,
            String prefix,
            byte[] content) {

        // https://github.com/debezium/debezium/blob/6246808308200ae9877f25f3a04e378578def98c/debezium-connector-postgres/src/main/java/io/debezium/connector/postgresql/connection/pgoutput/PgOutputMessageDecoder.java#L599
        private static LogicalDecodingMessage parse(final ByteBuffer buffer) {
            final boolean transactional = buffer.get() == 1;
            final LogSequenceNumber lsn = LogSequenceNumber.valueOf(buffer.getLong());
            final String prefix = getString(buffer);
            final int contentLength = buffer.getInt();
            final byte[] content = new byte[contentLength];
            buffer.get(content);

            return new LogicalDecodingMessage(transactional, lsn, prefix, content);
        }

        private static String getString(final ByteBuffer buffer) {
            final var stringBuilder = new StringBuilder();

            byte b;
            while ((b = buffer.get()) != 0) {
                stringBuilder.append((char) b);
            }

            return stringBuilder.toString();
        }

    }

    private void ensurePublication(final Connection connection) throws SQLException {
        try (final Statement statement = connection.createStatement()) {
            statement.execute("CREATE PUBLICATION " + PUBLICATION_NAME);
        } catch (PSQLException e) {
            // TODO: Is there an error code for this?
            if (!e.getMessage().contains("already exists")) {
                throw e;
            }
        }
    }

    private void ensureReplicationSlot(final Connection connection) throws SQLException {
        try {
            connection.unwrap(PGConnection.class).getReplicationAPI()
                    .createReplicationSlot()
                    .logical()
                    .withSlotName(REPLICATION_SLOT_NAME)
                    .withOutputPlugin("pgoutput")
                    .make();
        } catch (PSQLException e) {
            // TODO: Is there an error code for this?
            if (!e.getMessage().contains("already exists")) {
                throw e;
            }
        }
    }

    private PGReplicationStream startReplicationStream(final Connection connection) throws SQLException {
        return connection.unwrap(PGConnection.class).getReplicationAPI()
                .replicationStream()
                .logical()
                // https://www.postgresql.org/docs/current/protocol-logical-replication.html#PROTOCOL-LOGICAL-REPLICATION-PARAMS
                .withSlotOption("proto_version", "2")
                .withSlotOption("publication_names", PUBLICATION_NAME)
                .withSlotOption("messages", "true")
                .withSlotName(REPLICATION_SLOT_NAME)
                .withStatusInterval(5, TimeUnit.SECONDS) // TODO: What's a reasonable value?
                .start();
    }

}
