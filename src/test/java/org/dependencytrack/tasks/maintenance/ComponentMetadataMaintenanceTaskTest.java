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
package org.dependencytrack.tasks.maintenance;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.maintenance.ComponentMetadataMaintenanceEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.junit.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

public class ComponentMetadataMaintenanceTaskTest extends PersistenceCapableTest {

    @Test
    public void test() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        qm.persist(component);

        final Instant now = Instant.now();

        final var integrityMetadata = new IntegrityMetaComponent();
        integrityMetadata.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        integrityMetadata.setLastFetch(Date.from(now));
        qm.persist(integrityMetadata);

        final var orphanedIntegrityMetadata = new IntegrityMetaComponent();
        orphanedIntegrityMetadata.setPurl("pkg:maven/foo/bar@1.2.3");
        orphanedIntegrityMetadata.setLastFetch(Date.from(now));
        qm.persist(orphanedIntegrityMetadata);

        final var repoMetadata = new RepositoryMetaComponent();
        repoMetadata.setRepositoryType(RepositoryType.MAVEN);
        repoMetadata.setNamespace("com.acme");
        repoMetadata.setName("acme-lib");
        repoMetadata.setLatestVersion("2.0.0");
        repoMetadata.setLastCheck(Date.from(now.minus(29, ChronoUnit.DAYS)));
        qm.persist(repoMetadata);

        final var orphanedRepoMetadata = new RepositoryMetaComponent();
        orphanedRepoMetadata.setRepositoryType(RepositoryType.MAVEN);
        orphanedRepoMetadata.setNamespace("foo");
        orphanedRepoMetadata.setName("bar");
        orphanedRepoMetadata.setLatestVersion("3.2.1");
        orphanedRepoMetadata.setLastCheck(Date.from(now.minus(31, ChronoUnit.DAYS)));
        qm.persist(orphanedRepoMetadata);

        final var task = new ComponentMetadataMaintenanceTask();
        assertThatNoException().isThrownBy(() -> task.inform(new ComponentMetadataMaintenanceEvent()));

        assertThat(qm.getIntegrityMetaComponent("pkg:maven/com.acme/acme-lib@1.0.0")).isNotNull();
        assertThat(qm.getIntegrityMetaComponent("pkg:maven/foo/bar@1.2.3")).isNull();
        assertThat(qm.getRepositoryMetaComponent(RepositoryType.MAVEN, "com.acme", "acme-lib")).isNotNull();
        assertThat(qm.getRepositoryMetaComponent(RepositoryType.MAVEN, "foo", "bar")).isNull();
    }

}