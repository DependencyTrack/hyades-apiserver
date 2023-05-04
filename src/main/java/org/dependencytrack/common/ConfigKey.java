package org.dependencytrack.common;

import alpine.Config;

import java.time.Duration;

public enum ConfigKey implements Config.Key {

    SNYK_THREAD_POOL_SIZE("snyk.thread.pool.size", 10),
    SNYK_RETRY_MAX_ATTEMPTS("snyk.retry.max.attempts", 10),
    SNYK_RETRY_EXPONENTIAL_BACKOFF_MULTIPLIER("snyk.retry.exponential.backoff.multiplier", 2),
    SNYK_RETRY_EXPONENTIAL_BACKOFF_INITIAL_DURATION_SECONDS("snyk.retry.exponential.backoff.initial.duration.seconds", 1),
    SNYK_RETRY_EXPONENTIAL_BACKOFF_MAX_DURATION_SECONDS("snyk.retry.exponential.backoff.max.duration.seconds", 60),
    OSSINDEX_REQUEST_MAX_PURL("ossindex.request.max.purl", 128),
    OSSINDEX_RETRY_EXPONENTIAL_BACKOFF_MAX_ATTEMPTS("ossindex.retry.backoff.max.attempts", 10),
    OSSINDEX_RETRY_EXPONENTIAL_BACKOFF_MULTIPLIER("ossindex.retry.backoff.multiplier", 2),
    OSSINDEX_RETRY_EXPONENTIAL_BACKOFF_MAX_DURATION("ossindex.retry.backoff.max.duration", Duration.ofMinutes(10).toMillis()),
    SYSTEM_REQUIREMENT_CHECK_ENABLED("system.requirement.check.enabled", true),
    APPLICATION_ID("application.id", "dependencytrack-apiserver"),
    KAFKA_BOOTSTRAP_SERVERS("kafka.bootstrap.servers", null),
    KAFKA_AUTO_OFFSET_RESET("kafka.auto.offset.reset", "earliest"),

    KAFKA_TLS_PROTOCOL("kafka.security.protocol", ""),

    KAFKA_TLS_ENABLED("kafka.tls.enabled", false),
    KAFKA_MTLS_ENABLED("kafka.mtls.enabled", false),
    TRUST_STORE_PATH("kafka.truststore.path", ""),

    TRUST_STORE_PASSWORD("kafka.truststore.password", ""),
    KEY_STORE_PATH("kafka.keystore.path", ""),

    KEY_STORE_PASSWORD("kafka.keystore.password", ""),
    KAFKA_NUM_STREAM_THREADS("kafka.num.stream.threads", 1),
    KAFKA_TOPIC_PREFIX("api.topic.prefix", ""),
    KAFKA_STREAMS_METRICS_RECORDING_LEVEL("kafka.streams.metrics.recording.level", "INFO");

    private final String propertyName;
    private final Object defaultValue;

    ConfigKey(final String propertyName, final Object defaultValue) {
        this.propertyName = propertyName;
        this.defaultValue = defaultValue;
    }

    @Override
    public String getPropertyName() {
        return propertyName;
    }

    @Override
    public Object getDefaultValue() {
        return defaultValue;
    }

}
