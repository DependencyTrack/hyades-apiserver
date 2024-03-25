package org.dependencytrack.event.kafka.streams.exception;

import alpine.Config;
import alpine.common.logging.Logger;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.errors.RecordTooLargeException;
import org.apache.kafka.streams.errors.ProductionExceptionHandler;
import org.dependencytrack.common.ConfigKey;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;

public class KafkaStreamsProductionExceptionHandler extends AbstractThresholdBasedExceptionHandler implements ProductionExceptionHandler {

    private static final Logger LOGGER = Logger.getLogger(KafkaStreamsProductionExceptionHandler.class);


    @SuppressWarnings("unused") // Called by Kafka Streams via reflection
    public KafkaStreamsProductionExceptionHandler() {
        this(
                Clock.systemUTC(),
                Duration.parse(Config.getInstance().getProperty(ConfigKey.KAFKA_STREAMS_DESERIALIZATION_EXCEPTION_THRESHOLD_INTERVAL)),
                Config.getInstance().getPropertyAsInt(ConfigKey.KAFKA_STREAMS_DESERIALIZATION_EXCEPTION_THRESHOLD_COUNT)
        );
    }

    KafkaStreamsProductionExceptionHandler(final Clock clock,
                                           final Duration exceptionThresholdInterval,
                                           final int exceptionThresholdCount) {
        super(clock, exceptionThresholdInterval, exceptionThresholdCount);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void configure(final Map<String, ?> configs) {
        // Configuration is done via Alpine config.
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

        if (exceedsThreshold()) {
            LOGGER.error("""
                    Failed to produce record to topic %s; \
                    Stopping to produce records, as the error was encountered %d times since %s, \
                    exceeding the configured threshold of %d occurrences in an interval of %s\
                    """
                    .formatted(record.topic(),
                            exceptionOccurrences(), firstExceptionOccurredAt(),
                            exceptionThresholdCount(), exceptionThresholdInterval()), exception);
            return ProductionExceptionHandlerResponse.FAIL;
        }

        LOGGER.warn("""
                Failed to produce record to topic %s; \
                Skipping and continuing to produce records, as the configured threshold of \
                %d occurrences in an interval of %s has not been exceeded yet\
                """
                .formatted(record.topic(), exceptionThresholdCount(), exceptionThresholdInterval()), exception);
        return ProductionExceptionHandlerResponse.CONTINUE;
    }

}
