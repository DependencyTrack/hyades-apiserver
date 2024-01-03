package org.dependencytrack.event.kafka.streams.exception;

import alpine.Config;
import alpine.common.logging.Logger;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.kafka.streams.errors.StreamsUncaughtExceptionHandler;
import org.datanucleus.api.jdo.exceptions.ConnectionInUseException;
import org.datanucleus.store.query.QueryInterruptedException;
import org.dependencytrack.common.ConfigKey;

import javax.jdo.JDOOptimisticVerificationException;
import java.net.SocketTimeoutException;
import java.sql.SQLTransientException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;

import static org.apache.kafka.streams.errors.StreamsUncaughtExceptionHandler.StreamThreadExceptionResponse.REPLACE_THREAD;
import static org.apache.kafka.streams.errors.StreamsUncaughtExceptionHandler.StreamThreadExceptionResponse.SHUTDOWN_CLIENT;

public class KafkaStreamsUncaughtExceptionHandler implements StreamsUncaughtExceptionHandler {

    private record ExceptionOccurrence(Instant occurredFirstAt, int count) {
    }

    private static final Logger LOGGER = Logger.getLogger(KafkaStreamsUncaughtExceptionHandler.class);

    private final Clock clock;
    private final Map<Class<? extends Throwable>, ExceptionOccurrence> transientExceptionOccurrences;
    private final Duration transientExceptionThresholdInterval;
    private final int transientExceptionThresholdCount;

    public KafkaStreamsUncaughtExceptionHandler() {
        this(
                Clock.systemUTC(),
                Duration.parse(Config.getInstance().getProperty(ConfigKey.KAFKA_STREAMS_TRANSIENT_PROCESSING_EXCEPTION_THRESHOLD_INTERVAL)),
                Config.getInstance().getPropertyAsInt(ConfigKey.KAFKA_STREAMS_TRANSIENT_PROCESSING_EXCEPTION_THRESHOLD_COUNT)
        );
    }

    KafkaStreamsUncaughtExceptionHandler(final Clock clock,
                                         final Duration transientExceptionThresholdInterval,
                                         final int transientExceptionThresholdCount) {
        this.clock = clock;
        this.transientExceptionOccurrences = new ConcurrentHashMap<>();
        this.transientExceptionThresholdInterval = transientExceptionThresholdInterval;
        this.transientExceptionThresholdCount = transientExceptionThresholdCount;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StreamThreadExceptionResponse handle(final Throwable exception) {
        final Throwable rootCause = ExceptionUtils.getRootCause(exception);

        if (rootCause instanceof TimeoutException
                || rootCause instanceof ConnectTimeoutException
                || rootCause instanceof SocketTimeoutException
                || rootCause instanceof ConnectionInUseException
                || rootCause instanceof QueryInterruptedException
                || rootCause instanceof JDOOptimisticVerificationException
                || rootCause instanceof SQLTransientException) {
            final ExceptionOccurrence occurrence = transientExceptionOccurrences
                    .compute(rootCause.getClass(), (key, oldValue) -> {
                        final Instant now = Instant.now(clock);
                        if (oldValue == null) {
                            return new ExceptionOccurrence(now, 1);
                        }

                        final Instant cutoff = oldValue.occurredFirstAt().plus(transientExceptionThresholdInterval);
                        if (now.isAfter(cutoff)) {
                            return new ExceptionOccurrence(now, 1);
                        }

                        return new ExceptionOccurrence(oldValue.occurredFirstAt(), oldValue.count() + 1);
                    });

            if (occurrence.count() >= transientExceptionThresholdCount) {
                LOGGER.error("""
                        Encountered an unhandled exception during record processing; \
                        Shutting down the failed stream thread as the error was encountered \
                        %d times since %s, exceeding the configured threshold of %d occurrences \
                        in an interval of %s\
                        """
                        // Actual exception stack trace will be logged by Kafka Streams
                        .formatted(occurrence.count(), occurrence.occurredFirstAt(),
                                transientExceptionThresholdCount, transientExceptionThresholdInterval));
                return SHUTDOWN_CLIENT;
            }

            LOGGER.warn("""
                    Encountered an unhandled exception during record processing; \
                    Replacing the failed stream thread as the error appears to be transient\
                    """); // Actual exception stack trace will be logged by Kafka Streams
            return REPLACE_THREAD;
        }

        LOGGER.error("""
                Encountered an unhandled exception during record processing; \
                Shutting down the failed stream thread as the error does not appear to be transient\
                """); // Actual exception stack trace will be logged by Kafka Streams
        return SHUTDOWN_CLIENT;
    }

}
