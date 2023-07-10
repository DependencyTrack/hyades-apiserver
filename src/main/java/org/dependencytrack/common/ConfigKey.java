package org.dependencytrack.common;

import alpine.Config;

public enum ConfigKey implements Config.Key {

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
    KAFKA_STREAMS_METRICS_RECORDING_LEVEL("kafka.streams.metrics.recording.level", "INFO"),
    TASK_PORTFOLIO_LOCK_AT_MOST_FOR("task.metrics.portfolio.lockAtMostForInMillis", "900000"),
    TASK_PORTFOLIO_LOCK_AT_LEAST_FOR("task.metrics.portfolio.lockAtLeastForInMillis", "3000"),
    TASK_METRICS_VULNERABILITY_LOCK_AT_MOST_FOR("task.metrics.vulnerability.lockAtMostForInMillis", "900000"),
    TASK_METRICS_VULNERABILITY_LOCK_AT_LEAST_FOR("task.metrics.vulnerability.lockAtLeastForInMillis", "3000"),
    TASK_MIRROR_EPSS_LOCK_AT_MOST_FOR("task.mirror.epss.lockAtMostForInMillis", "900000"),
    TASK_MIRROR_EPSS_LOCK_AT_LEAST_FOR("task.mirror.epss.lockAtLeastForInMillis", "3000"),
    TASK_COMPONENT_IDENTIFICATION_LOCK_AT_MOST_FOR("task.componentIdentification.lockAtMostForInMillis", "900000"),
    TASK_COMPONENT_IDENTIFICATION_LOCK_AT_LEAST_FOR("task.componentIdentification.lockAtLeastForInMillis", "3000"),
    TASK_LDAP_SYNC_LOCK_AT_MOST_FOR("task.ldapSync.lockAtMostForInMillis", "900000"),
    TASK_LDAP_SYNC_LOCK_AT_LEAST_FOR("task.ldapSync.lockAtLeastForInMillis", "3000"),
    BOM_UPLOAD_PROCESSING_TRX_FLUSH_THRESHOLD("bom.upload.processing.trx.flush.threshold", "10000");

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
