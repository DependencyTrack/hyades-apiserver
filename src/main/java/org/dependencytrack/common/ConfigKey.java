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

    TASK_SCHEDULER_INITIAL_DELAY("task.scheduler.initial.delay", "180000"),
    TASK_SCHEDULER_POLLING_INTERVAL("task.scheduler.polling.interval", "60000"),
    TMP_DELAY_BOM_PROCESSED_NOTIFICATION("tmp.delay.bom.processed.notification", "false"),
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
    DATABASE_RUN_MIGRATIONS_ONLY("database.run.migrations.only", false),
    INIT_TASKS_ENABLED("init.tasks.enabled", true),
    INIT_AND_EXIT("init.and.exit", false),

    DEV_SERVICES_ENABLED("dev.services.enabled", false),
    DEV_SERVICES_IMAGE_FRONTEND("dev.services.image.frontend", "ghcr.io/dependencytrack/hyades-frontend:snapshot"),
    DEV_SERVICES_IMAGE_KAFKA("dev.services.image.kafka", "apache/kafka-native:3.9.0"),
    DEV_SERVICES_IMAGE_POSTGRES("dev.services.image.postgres", "postgres:13-alpine");

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
