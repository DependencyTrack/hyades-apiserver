package org.dependencytrack.event.kafka.exception;

import alpine.Config;
import alpine.common.logging.Logger;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.errors.RecordTooLargeException;
import org.apache.kafka.streams.errors.ProductionExceptionHandler;
import org.dependencytrack.common.ConfigKey;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

public class KafkaStreamsProductionExceptionHandler implements ProductionExceptionHandler {

    private static final Logger LOGGER = Logger.getLogger(KafkaStreamsProductionExceptionHandler.class);

    private final Duration exceptionThresholdInterval;
    private final int exceptionThresholdCount;
    private Instant firstExceptionOccurredAt;
    private int exceptionOccurrences;

    @SuppressWarnings("unused") // Called by Kafka Streams via reflection
    public KafkaStreamsProductionExceptionHandler() {
        this(
                Duration.parse(Config.getInstance().getProperty(ConfigKey.KAFKA_STREAMS_DESERIALIZATION_EXCEPTION_THRESHOLD_INTERVAL)),
                Config.getInstance().getPropertyAsInt(ConfigKey.KAFKA_STREAMS_DESERIALIZATION_EXCEPTION_THRESHOLD_COUNT)
        );
    }

    KafkaStreamsProductionExceptionHandler(final Duration exceptionThresholdInterval,
                                           final int exceptionThresholdCount) {
        this.exceptionThresholdInterval = exceptionThresholdInterval;
        this.exceptionThresholdCount = exceptionThresholdCount;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void configure(final Map<String, ?> configs) {
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized ProductionExceptionHandlerResponse handle(final ProducerRecord<byte[], byte[]> record,
                                                                  final Exception exception) {
        if (!(exception instanceof RecordTooLargeException)) {
            LOGGER.error("""
                    Failed to produce record to topic %s; \
                    Stopping to produce records, as the error is of an unexpected type, \
                    and we're not sure if it can safely be ignored\
                    """
                    .formatted(record.topic()), exception);
            return ProductionExceptionHandlerResponse.FAIL;
        }

        final Instant now = Instant.now();
        if (firstExceptionOccurredAt == null) {
            firstExceptionOccurredAt = now;
            exceptionOccurrences = 1;
        } else {
            exceptionOccurrences++;
        }

        final Instant cutoff = firstExceptionOccurredAt.plus(exceptionThresholdInterval);
        if (now.isAfter(cutoff)) {
            firstExceptionOccurredAt = now;
            exceptionOccurrences = 1;
        }

        if (exceptionOccurrences >= exceptionThresholdCount) {
            LOGGER.error("""
                    Failed to produce record to topic %s; \
                    Stopping to produce records, as the error was encountered %d times since %s, \
                    exceeding the configured threshold of %d occurrences in an interval of %s\
                    """
                    .formatted(record.topic(),
                            exceptionOccurrences, firstExceptionOccurredAt,
                            exceptionThresholdCount, exceptionThresholdInterval), exception);
            return ProductionExceptionHandlerResponse.FAIL;
        }

        LOGGER.warn("""
                Failed to produce record to topic %s; \
                Skipping and continuing to produce records, as the configured threshold of \
                %d occurrences in an interval of %s has not been exceeded yet\
                """
                .formatted(record.topic(), exceptionThresholdCount, exceptionThresholdInterval), exception);
        return ProductionExceptionHandlerResponse.CONTINUE;
    }

}
