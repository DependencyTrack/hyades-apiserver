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

import org.jspecify.annotations.NullMarked;

@NullMarked
module org.dependencytrack.workflow.engine {
    provides org.dependencytrack.workflow.engine.api.WorkflowEngineFactory
            with org.dependencytrack.workflow.engine.WorkflowEngineFactoryImpl;

    requires com.fasterxml.uuid;
    requires com.github.benmanes.caffeine;
    requires com.google.protobuf.util;
    requires com.google.protobuf;
    requires io.github.resilience4j.core;
    requires java.sql;
    requires javacron;
    requires micrometer.core;
    requires transitive org.dependencytrack.proto;
    requires transitive org.dependencytrack.workflow.api;
    requires transitive org.dependencytrack.workflow.engine.api;
    requires transitive org.dependencytrack.workflow.engine.migration;
    requires org.jdbi.v3.core;
    requires org.jdbi.v3.freemarker;
    requires org.jdbi.v3.jackson2;
    requires org.jdbi.v3.json;
    requires org.jdbi.v3.postgres;
    requires transitive org.jspecify;
    requires org.postgresql.jdbc;
    requires org.slf4j;
}