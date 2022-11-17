package org.dependencytrack.event.kafka;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import io.micrometer.core.instrument.binder.kafka.KafkaClientMetrics;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.dependencytrack.RequirementsVerifier;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.kafka.serialization.JacksonSerializer;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Properties;

public class KafkaProducerInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(KafkaProducerInitializer.class);
    private static Producer<String, Object> PRODUCER;
    private static KafkaClientMetrics PRODUCER_METRICS;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing Kafka producer");
        if (RequirementsVerifier.failedValidation()) {
            LOGGER.warn("System requirements not satisfied, skipping");
            return;
        }

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

            // Close producer, but wait up to 5 seconds for it to send off
            // all queued events. Not sure what an appropriate timeout is.
            PRODUCER.close(Duration.of(5, ChronoUnit.SECONDS));

            if (PRODUCER_METRICS != null) {
                PRODUCER_METRICS.close();
            }
        }
    }

    public static Producer<String, Object> getProducer() {
        return PRODUCER;
    }

    private static Producer<String, Object> createProducer() {
        final var properties = new Properties();
        properties.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, Config.getInstance().getProperty(ConfigKey.KAFKA_BOOTSTRAP_SERVERS));
        properties.put(ProducerConfig.CLIENT_ID_CONFIG, Config.getInstance().getProperty(ConfigKey.KAFKA_APPLICATION_ID));
        properties.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        properties.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JacksonSerializer.class.getName());
        properties.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);
        properties.put(ProducerConfig.ACKS_CONFIG, "all");
        return new KafkaProducer<>(properties);
    }

}
