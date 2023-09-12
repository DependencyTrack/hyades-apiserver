package org.dependencytrack.common;

import alpine.Config;

import java.time.Duration;

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
    KAFKA_STREAMS_DESERIALIZATION_EXCEPTION_THRESHOLD_COUNT("kafka.streams.deserialization.exception.threshold.count", "5"),
    KAFKA_STREAMS_DESERIALIZATION_EXCEPTION_THRESHOLD_INTERVAL("kafka.streams.deserialization.exception.threshold.interval", "PT30M"),
    KAFKA_STREAMS_METRICS_RECORDING_LEVEL("kafka.streams.metrics.recording.level", "INFO"),
    KAFKA_STREAMS_PRODUCTION_EXCEPTION_THRESHOLD_COUNT("kafka.streams.production.exception.threshold.count", "5"),
    KAFKA_STREAMS_PRODUCTION_EXCEPTION_THRESHOLD_INTERVAL("kafka.streams.production.exception.threshold.interval", "PT30H"),
    KAFKA_STREAMS_TRANSIENT_PROCESSING_EXCEPTION_THRESHOLD_COUNT("kafka.streams.transient.processing.exception.threshold.count", "50"),
    KAFKA_STREAMS_TRANSIENT_PROCESSING_EXCEPTION_THRESHOLD_INTERVAL("kafka.streams.transient.processing.exception.threshold.interval", "PT30M"),

    CRON_EXPRESSION_FOR_PORTFOLIO_METRICS_TASK("task.cron.metrics.portfolio", "10 * * * *"),
    CRON_EXPRESSION_FOR_VULNERABILITY_METRICS_TASK("task.cron.metrics.vulnerability", "40 * * * *"),
    CRON_EXPRESSION_FOR_COMPONENT_IDENTIFICATION_TASK("task.cron.componentIdentification", "25 */6 * * *"),
    CRON_EXPRESSION_FOR_GITHUB_MIRRORING_TASK("task.cron.mirror.github", "0 2 * * *"),
    CRON_EXPRESSION_FOR_OSV_MIRRORING_TASK("task.cron.mirror.osv", "0 3 * * *"),
    CRON_EXPRESSION_FOR_NIST_MIRRORING_TASK("task.cron.mirror.nist", "0 4 * * *"),
    CRON_EXPRESSION_FOR_LDAP_SYNC_TASK("task.cron.ldapSync", "0 */6 * * *"),
    CRON_EXPRESSION_FOR_VULNDB_SYNC_TASK("task.cron.vulndbSync", "0 5 * * *"),
    CRON_EXPRESSION_FOR_REPO_META_ANALYSIS_TASK("task.cron.repoMetaAnalysis", "0 1 * * *"),
    CRON_EXPRESSION_FOR_VULN_ANALYSIS_TASK("task.cron.vulnAnalysis", "0 6 * * *"),
    CRON_EXPRESSION_FOR_VULN_SCAN_CLEANUP_TASK("task.cron.vulnScanCleanUp", "5 8 * * 4"),
    CRON_EXPRESSION_FOR_FORTIFY_SSC_SYNC("task.cron.fortify.ssc.sync", "0 2 * * *"),
    CRON_EXPRESSION_FOR_DEFECT_DOJO_SYNC("task.cron.defectdojo.sync", "0 2 * * *"),
    CRON_EXPRESSION_FOR_KENNA_SYNC("task.cron.kenna.sync", "0 2 * * *"),
    CRON_EXPRESSION_FOR_WORKFLOW_STATE_REAPER_TASK("task.cron.workflow.state.reaper", "*/15 * * * *"),
    TASK_SCHEDULER_INITIAL_DELAY("task.scheduler.initial.delay", "180000"),
    TASK_SCHEDULER_POLLING_INTERVAL("task.scheduler.polling.interval", "60000"),
    TASK_PORTFOLIO_LOCK_AT_MOST_FOR("task.metrics.portfolio.lockAtMostForInMillis", "900000"),
    TASK_PORTFOLIO_LOCK_AT_LEAST_FOR("task.metrics.portfolio.lockAtLeastForInMillis", "90000"),
    TASK_METRICS_VULNERABILITY_LOCK_AT_MOST_FOR("task.metrics.vulnerability.lockAtMostForInMillis", "900000"),
    TASK_METRICS_VULNERABILITY_LOCK_AT_LEAST_FOR("task.metrics.vulnerability.lockAtLeastForInMillis", "90000"),
    TASK_MIRROR_EPSS_LOCK_AT_MOST_FOR("task.mirror.epss.lockAtMostForInMillis", "900000"),
    TASK_MIRROR_EPSS_LOCK_AT_LEAST_FOR("task.mirror.epss.lockAtLeastForInMillis", "90000"),
    TASK_COMPONENT_IDENTIFICATION_LOCK_AT_MOST_FOR("task.componentIdentification.lockAtMostForInMillis", "900000"),
    TASK_COMPONENT_IDENTIFICATION_LOCK_AT_LEAST_FOR("task.componentIdentification.lockAtLeastForInMillis", "90000"),
    TASK_LDAP_SYNC_LOCK_AT_MOST_FOR("task.ldapSync.lockAtMostForInMillis", "900000"),
    TASK_LDAP_SYNC_LOCK_AT_LEAST_FOR("task.ldapSync.lockAtLeastForInMillis", "90000"),
    TASK_WORKFLOW_STEP_REAPER_LOCK_AT_MOST_FOR("task.workflow.state.reaper.lockAtMostForInMillis", String.valueOf(Duration.ofMinutes(15).toMillis())),
    TASK_WORKFLOW_STEP_REAPER_LOCK_AT_LEAST_FOR("task.workflow.state.reaper.lockAtLeastForInMillis", String.valueOf(Duration.ofMinutes(15).toMillis())),
    BOM_UPLOAD_PROCESSING_TRX_FLUSH_THRESHOLD("bom.upload.processing.trx.flush.threshold", "10000"),
    WORKFLOW_RETENTION_DURATION("workflow.retention.duration", "P3D"),
    WORKFLOW_STEP_TIMEOUT_DURATION("workflow.step.timeout.duration", "PT1H");

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
