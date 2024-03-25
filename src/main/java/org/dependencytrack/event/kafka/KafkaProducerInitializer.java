package org.dependencytrack.event.kafka;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import io.micrometer.core.instrument.binder.kafka.KafkaClientMetrics;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.MockProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.record.CompressionType;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.dependencytrack.common.ConfigKey;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.time.Duration;
import java.util.Map;
import java.util.Properties;

public class KafkaProducerInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(KafkaProducerInitializer.class);
    private static final Duration DRAIN_TIMEOUT_DURATION =
            Duration.parse(Config.getInstance().getProperty(ConfigKey.KAFKA_PRODUCER_DRAIN_TIMEOUT_DURATION));

    private static Producer<byte[], byte[]> PRODUCER;
    private static KafkaClientMetrics PRODUCER_METRICS;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing Kafka producer");

        PRODUCER = createProducer();

        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            LOGGER.info("Registering Kafka producer metrics");
            PRODUCER_METRICS = new KafkaClientMetrics(PRODUCER);
            PRODUCER_METRICS.bindTo(Metrics.getRegistry());
        }
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        if (PRODUCER != null) {
            LOGGER.info("Closing Kafka producer");

            // Close producer, but wait for a configurable amount of time for it to
            // send off all queued events.
            PRODUCER.close(DRAIN_TIMEOUT_DURATION);

            if (PRODUCER_METRICS != null) {
                PRODUCER_METRICS.close();
            }
        }
    }

    public static Producer<byte[], byte[]> getProducer() {
        if (PRODUCER == null && Config.isUnitTestsEnabled()) {
            // Workaround for tests, as we can't use dependency injection in JerseyTest.
            // Analog to how it's done for instantiation of PersistenceManagerFactory:
            // https://github.com/stevespringett/Alpine/blob/alpine-parent-2.2.0/alpine-server/src/main/java/alpine/server/persistence/PersistenceManagerFactory.java#L127-L135
            PRODUCER = new MockProducer<>(true, new ByteArraySerializer(), new ByteArraySerializer());
        }

        return PRODUCER;
    }

    /**
     * Closes the {@link KafkaProducer} and removes any reference to it.
     * <p>
     * This method should be called in the {@code tearDown} method of unit- and integration
     * tests that interact with the persistence layer.
     */
    public static void tearDown() {
        if (PRODUCER != null) {
            PRODUCER.close();
            PRODUCER = null;
        }
    }

    private static Producer<byte[], byte[]> createProducer() {
        final var properties = new Properties();
        properties.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, Config.getInstance().getProperty(ConfigKey.KAFKA_BOOTSTRAP_SERVERS));
        properties.put(ProducerConfig.CLIENT_ID_CONFIG, Config.getInstance().getProperty(ConfigKey.APPLICATION_ID));
        properties.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class.getName());
        properties.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class.getName());
        properties.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, CompressionType.SNAPPY.name);
        properties.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, "true");
        properties.put(ProducerConfig.ACKS_CONFIG, "all");
        if (Config.getInstance().getPropertyAsBoolean(ConfigKey.KAFKA_TLS_ENABLED)) {
            properties.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, Config.getInstance().getProperty(ConfigKey.KAFKA_TLS_PROTOCOL));
            properties.put(SslConfigs.SSL_TRUSTSTORE_LOCATION_CONFIG, Config.getInstance().getProperty(ConfigKey.TRUST_STORE_PATH));
            properties.put(SslConfigs.SSL_TRUSTSTORE_PASSWORD_CONFIG, Config.getInstance().getProperty(ConfigKey.TRUST_STORE_PASSWORD));
            if (Config.getInstance().getPropertyAsBoolean(ConfigKey.KAFKA_MTLS_ENABLED)) {
                properties.put(SslConfigs.SSL_KEYSTORE_LOCATION_CONFIG, Config.getInstance().getProperty(ConfigKey.KEY_STORE_PATH));
                properties.put(SslConfigs.SSL_KEYSTORE_PASSWORD_CONFIG, Config.getInstance().getProperty(ConfigKey.KEY_STORE_PASSWORD));
            }
        }

        final Map<String, String> passThroughProperties = Config.getInstance().getPassThroughProperties("kafka.producer");
        for (final Map.Entry<String, String> passThroughProperty : passThroughProperties.entrySet()) {
            final String key = passThroughProperty.getKey().replaceFirst("^kafka\\.producer\\.", "");
            if (ProducerConfig.configNames().contains(key)) {
                properties.put(key, passThroughProperty.getValue());
            } else {
                LOGGER.warn("%s is not a known Producer property; Ignoring".formatted(key));
            }
        }

        return new KafkaProducer<>(properties);
    }

}
