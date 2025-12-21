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
package org.dependencytrack.tasks;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TaskSchedulerInitializerTest {

    @Test
    public void shouldScheduleTasks() {
        final var scheduler = new TaskScheduler();

        final var initializer = new TaskSchedulerInitializer(scheduler);
        initializer.contextInitialized(null);

        assertThat(scheduler.scheduledTaskIds()).containsExactlyInAnyOrder(
                "CSAF Document Import",
                "Component Metadata Maintenance",
                "Defect Dojo Upload",
                "EPSS Mirror",
                "Fortify SSC Upload",
                "GitHub Advisories Mirror",
                "Internal Component Identification",
                "Kenna Security Upload",
                "LDAP Sync",
                "Metrics Maintenance",
                "NVD Mirror",
                "OSV Mirror",
                "Portfolio Metrics Update",
                "Portfolio Repository Meta Analysis",
                "Portfolio Vulnerability Analysis",
                "Project Maintenance",
                "Tag Maintenance",
                "Vulnerability Database Maintenance",
                "Vulnerability Metrics Update",
                "Vulnerability Policy Sync",
                "Vulnerability Scan Maintenance",
                "Workflow Maintenance");

        assertThat(scheduler.isRunning()).isTrue();

        initializer.contextDestroyed(null);

        assertThat(scheduler.isRunning()).isFalse();
    }

}