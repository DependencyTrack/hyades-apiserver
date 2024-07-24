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
package org.dependencytrack.common;

import alpine.Config;

import java.time.Duration;

public enum ConfigKey implements Config.Key {

    ALPINE_WORKER_POOL_DRAIN_TIMEOUT_DURATION("alpine.worker.pool.drain.timeout.duration", "PT30S"),

    KAFKA_AUTO_OFFSET_RESET("kafka.auto.offset.reset", "earliest"),
    KAFKA_BOOTSTRAP_SERVERS("kafka.bootstrap.servers", null),
    KAFKA_KEY_STORE_PASSWORD("kafka.keystore.password", ""),
    KAFKA_KEY_STORE_PATH("kafka.keystore.path", ""),
    KAFKA_MTLS_ENABLED("kafka.mtls.enabled", false),
    KAFKA_PRODUCER_DRAIN_TIMEOUT_DURATION("kafka.producer.drain.timeout.duration", "PT30S"),
    KAFKA_TLS_ENABLED("kafka.tls.enabled", false),
    KAFKA_TLS_PROTOCOL("kafka.security.protocol", ""),
    DT_KAFKA_TOPIC_PREFIX("dt.kafka.topic.prefix", ""),
    KAFKA_TRUST_STORE_PASSWORD("kafka.truststore.password", ""),
    KAFKA_TRUST_STORE_PATH("kafka.truststore.path", ""),

    CRON_EXPRESSION_FOR_PORTFOLIO_METRICS_TASK("task.cron.metrics.portfolio", "10 * * * *"),
    CRON_EXPRESSION_FOR_VULNERABILITY_METRICS_TASK("task.cron.metrics.vulnerability", "40 * * * *"),
    CRON_EXPRESSION_FOR_COMPONENT_IDENTIFICATION_TASK("task.cron.componentIdentification", "25 */6 * * *"),
    CRON_EXPRESSION_FOR_EPSS_MIRRORING_TASK("task.cron.mirror.epss", "0 1 * * *"),
    CRON_EXPRESSION_FOR_GITHUB_MIRRORING_TASK("task.cron.mirror.github", "0 2 * * *"),
    CRON_EXPRESSION_FOR_OSV_MIRRORING_TASK("task.cron.mirror.osv", "0 3 * * *"),
    CRON_EXPRESSION_FOR_NIST_MIRRORING_TASK("task.cron.mirror.nist", "0 4 * * *"),
    CRON_EXPRESSION_FOR_VULNERABILITY_POLICY_BUNDLE_FETCH_TASK("task.cron.vulnerability.policy.bundle.fetch", "*/5 * * * *"),
    CRON_EXPRESSION_FOR_LDAP_SYNC_TASK("task.cron.ldapSync", "0 */6 * * *"),
    CRON_EXPRESSION_FOR_REPO_META_ANALYSIS_TASK("task.cron.repoMetaAnalysis", "0 1 * * *"),
    CRON_EXPRESSION_FOR_VULN_ANALYSIS_TASK("task.cron.vulnAnalysis", "0 6 * * *"),
    CRON_EXPRESSION_FOR_VULN_SCAN_CLEANUP_TASK("task.cron.vulnScanCleanUp", "5 8 * * 4"),
    CRON_EXPRESSION_FOR_FORTIFY_SSC_SYNC("task.cron.fortify.ssc.sync", "0 2 * * *"),
    CRON_EXPRESSION_FOR_DEFECT_DOJO_SYNC("task.cron.defectdojo.sync", "0 2 * * *"),
    CRON_EXPRESSION_FOR_KENNA_SYNC("task.cron.kenna.sync", "0 2 * * *"),
    CRON_EXPRESSION_FOR_WORKFLOW_STATE_CLEANUP_TASK("task.cron.workflow.state.cleanup", "*/15 * * * *"),
    CRON_EXPRESSION_FOR_INTEGRITY_META_INITIALIZER_TASK("task.cron.integrityInitializer", "0 */12 * * *"),
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
    TASK_WORKFLOW_STEP_CLEANUP_LOCK_AT_MOST_FOR("task.workflow.state.cleanup.lockAtMostForInMillis", String.valueOf(Duration.ofMinutes(15).toMillis())),
    TASK_WORKFLOW_STEP_CLEANUP_LOCK_AT_LEAST_FOR("task.workflow.state.cleanup.lockAtLeastForInMillis", String.valueOf(Duration.ofMinutes(15).toMillis())),
    TASK_PORTFOLIO_REPO_META_ANALYSIS_LOCK_AT_MOST_FOR("task.portfolio.repoMetaAnalysis.lockAtMostForInMillis", String.valueOf(Duration.ofMinutes(15).toMillis())),
    TASK_PORTFOLIO_REPO_META_ANALYSIS_LOCK_AT_LEAST_FOR("task.portfolio.repoMetaAnalysis.lockAtLeastForInMillis", String.valueOf(Duration.ofMinutes(5).toMillis())),
    TASK_PORTFOLIO_VULN_ANALYSIS_LOCK_AT_MOST_FOR("task.portfolio.vulnAnalysis.lockAtMostForInMillis", String.valueOf(Duration.ofMinutes(15).toMillis())),
    TASK_PORTFOLIO_VULN_ANALYSIS_LOCK_AT_LEAST_FOR("task.portfolio.vulnAnalysis.lockAtLeastForInMillis", String.valueOf(Duration.ofMinutes(5).toMillis())),
    TASK_VULNERABILITY_POLICY_BUNDLE_FETCH_LOCK_AT_MOST_FOR("task.vulnerability.policy.bundle.fetch.lockAtMostForInMillis", String.valueOf(Duration.ofMinutes(5).toMillis())),
    TASK_VULNERABILITY_POLICY_BUNDLE_FETCH_LOCK_AT_LEAST_FOR("task.vulnerability.policy.bundle.fetch.lockAtLeastForInMillis", String.valueOf(Duration.ofSeconds(5).toMillis())),
    BOM_UPLOAD_PROCESSING_TRX_FLUSH_THRESHOLD("bom.upload.processing.trx.flush.threshold", "10000"),
    WORKFLOW_RETENTION_DURATION("workflow.retention.duration", "P3D"),
    WORKFLOW_STEP_TIMEOUT_DURATION("workflow.step.timeout.duration", "PT1H"),
    TMP_DELAY_BOM_PROCESSED_NOTIFICATION("tmp.delay.bom.processed.notification", "false"),
    INTEGRITY_META_INITIALIZER_LOCK_AT_MOST_FOR("integrityMetaInitializer.lockAtMostForInMillis", String.valueOf(Duration.ofMinutes(15).toMillis())),
    INTEGRITY_META_INITIALIZER_LOCK_AT_LEAST_FOR("integrityMetaInitializer.lockAtLeastForInMillis", String.valueOf(Duration.ofMinutes(5).toMillis())),
    INTEGRITY_INITIALIZER_ENABLED("integrity.initializer.enabled", "false"),
    INTEGRITY_CHECK_ENABLED("integrity.check.enabled", "false"),
    VULNERABILITY_POLICY_ANALYSIS_ENABLED("vulnerability.policy.analysis.enabled", false),
    VULNERABILITY_POLICY_BUNDLE_URL("vulnerability.policy.bundle.url", null),
    VULNERABILITY_POLICY_BUNDLE_SOURCE_TYPE("vulnerability.policy.bundle.source.type", "NGINX"),
    VULNERABILITY_POLICY_BUNDLE_AUTH_USERNAME( "vulnerability.policy.bundle.auth.username", null),
    VULNERABILITY_POLICY_BUNDLE_AUTH_BEARER_TOKEN("vulnerability.policy.bundle.auth.bearer.token", null),
    VULNERABILITY_POLICY_BUNDLE_AUTH_PASSWORD( "vulnerability.policy.bundle.auth.password", null),
    VULNERABILITY_POLICY_S3_ACCESS_KEY("vulnerability.policy.s3.access.key", null),
    VULNERABILITY_POLICY_S3_SECRET_KEY("vulnerability.policy.s3.secret.key", null),
    VULNERABILITY_POLICY_S3_BUCKET_NAME("vulnerability.policy.s3.bucket.name", null),
    VULNERABILITY_POLICY_S3_BUNDLE_NAME("vulnerability.policy.s3.bundle.name", null),
    VULNERABILITY_POLICY_S3_REGION("vulnerability.policy.s3.region", null),
    DATABASE_MIGRATION_URL("database.migration.url", null),
    DATABASE_MIGRATION_USERNAME("database.migration.username", null),
    DATABASE_MIGRATION_PASSWORD("database.migration.password", null),
    DATABASE_RUN_MIGRATIONS("database.run.migrations", true),

    DEV_SERVICES_ENABLED("dev.services.enabled", false),
    DEV_SERVICES_IMAGE_FRONTEND("dev.services.image.frontend", "ghcr.io/dependencytrack/hyades-frontend:snapshot"),
    DEV_SERVICES_IMAGE_KAFKA("dev.services.image.kafka", "docker.redpanda.com/vectorized/redpanda:v24.1.11"),
    DEV_SERVICES_IMAGE_POSTGRES("dev.services.image.postgres", "postgres:16");

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
