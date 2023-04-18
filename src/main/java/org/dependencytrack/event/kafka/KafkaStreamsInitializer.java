package org.dependencytrack.event.kafka;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import io.micrometer.core.instrument.binder.kafka.KafkaStreamsMetrics;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.record.CompressionType;
import org.apache.kafka.streams.KafkaStreams;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.errors.LogAndContinueExceptionHandler;
import org.dependencytrack.RequirementsVerifier;
import org.dependencytrack.common.ConfigKey;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Properties;

public class KafkaStreamsInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(KafkaStreamsInitializer.class);

    private static KafkaStreams STREAMS;
    private static KafkaStreamsMetrics STREAMS_METRICS;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing Kafka streams");
        if (RequirementsVerifier.failedValidation()) {
            LOGGER.warn("System requirements not satisfied, skipping");
            return;
        }

        STREAMS = new KafkaStreams(new KafkaStreamsTopologyFactory().createTopology(), new StreamsConfig(getDefaultProperties()));

        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            LOGGER.info("Registering Kafka streams metrics");
            STREAMS_METRICS = new KafkaStreamsMetrics(STREAMS);
            STREAMS_METRICS.bindTo(Metrics.getRegistry());
        }

        STREAMS.start();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        if (STREAMS != null) {
            LOGGER.info("Closing Kafka streams");

            if (STREAMS_METRICS != null) {
                STREAMS_METRICS.close();
            }

            // Close streams, but wait up to 5 seconds for it to process
            // any queued events. Not sure what an appropriate timeout is.
            STREAMS.close(Duration.of(5, ChronoUnit.SECONDS));
        }
    }

    public static KafkaStreams getKafkaStreams() {
        return STREAMS;
    }

    static Properties getDefaultProperties() {
        final var properties = new Properties();
        properties.put(StreamsConfig.BOOTSTRAP_SERVERS_CONFIG, Config.getInstance().getProperty(ConfigKey.KAFKA_BOOTSTRAP_SERVERS));
        StringBuilder applicationName = new StringBuilder(Config.getInstance().getProperty(ConfigKey.KAFKA_TOPIC_PREFIX)).append(Config.getInstance().getProperty(ConfigKey.APPLICATION_ID));
        properties.put(StreamsConfig.APPLICATION_ID_CONFIG, applicationName.toString());

        properties.put(StreamsConfig.DEFAULT_DESERIALIZATION_EXCEPTION_HANDLER_CLASS_CONFIG, LogAndContinueExceptionHandler.class);
        properties.put(StreamsConfig.NUM_STREAM_THREADS_CONFIG, Config.getInstance().getProperty(ConfigKey.KAFKA_NUM_STREAM_THREADS));
        properties.put(StreamsConfig.STATE_DIR_CONFIG, Paths.get(Config.getInstance().getDataDirectorty().getAbsolutePath(), "kafka-streams").toString());
        properties.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, Config.getInstance().getProperty(ConfigKey.KAFKA_AUTO_OFFSET_RESET));
        if (Config.getInstance().getPropertyAsBoolean(ConfigKey.KAFKA_TLS_ENABLED)) {
            properties.put(StreamsConfig.SECURITY_PROTOCOL_CONFIG, Config.getInstance().getProperty(ConfigKey.KAFKA_TLS_PROTOCOL));
            properties.put(SslConfigs.SSL_TRUSTSTORE_LOCATION_CONFIG, Config.getInstance().getProperty(ConfigKey.TRUST_STORE_PATH));
            properties.put(SslConfigs.SSL_TRUSTSTORE_PASSWORD_CONFIG, Config.getInstance().getProperty(ConfigKey.TRUST_STORE_PASSWORD));
            if (Config.getInstance().getPropertyAsBoolean(ConfigKey.KAFKA_MTLS_ENABLED)) {
                properties.put(SslConfigs.SSL_KEYSTORE_LOCATION_CONFIG, Config.getInstance().getProperty(ConfigKey.KEY_STORE_PATH));
                properties.put(SslConfigs.SSL_KEYSTORE_PASSWORD_CONFIG, Config.getInstance().getProperty(ConfigKey.KEY_STORE_PASSWORD));
            }
        }
        properties.put(StreamsConfig.COMMIT_INTERVAL_MS_CONFIG, "1000");
        properties.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, CompressionType.SNAPPY.name);
        properties.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, "true");
        properties.put(ProducerConfig.ACKS_CONFIG, "all");
        return properties;
    }

}
