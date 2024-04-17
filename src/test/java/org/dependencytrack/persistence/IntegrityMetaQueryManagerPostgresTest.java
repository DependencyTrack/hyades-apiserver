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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.Project;
import org.junit.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class IntegrityMetaQueryManagerPostgresTest extends PersistenceCapableTest {

    @Test
    public void testCreateIntegrityMetadataHandlingConflict() {
        var integrityMeta = new IntegrityMetaComponent();
        integrityMeta.setPurl("pkg:maven/acme/example@1.0.0?type=jar");
        integrityMeta.setStatus(FetchStatus.IN_PROGRESS);
        integrityMeta.setLastFetch(new Date());
        qm.createIntegrityMetaHandlingConflict(integrityMeta);

        var integrityMeta2 = new IntegrityMetaComponent();
        //inserting same purl twice should not cause exception
        integrityMeta2.setPurl("pkg:maven/acme/example@1.0.0?type=jar");
        integrityMeta2.setStatus(FetchStatus.IN_PROGRESS);
        integrityMeta2.setLastFetch(new Date());
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
    }

    @Test
    public void testSynchronizeIntegrityMetaComponent() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setPurl("pkg:maven/acme/example@1.0.0?type=jar");
        component.setName("acme-lib");

        // without any component in database
        qm.synchronizeIntegrityMetaComponent();
        assertThat(qm.getIntegrityMetaComponent(component.getPurl().toString())).isNull();

        // with existing component in database
        qm.persist(component);
        qm.synchronizeIntegrityMetaComponent();
        assertThat(qm.getIntegrityMetaComponent(component.getPurl().toString())).satisfies(
                meta -> {
                    assertThat(meta.getStatus()).isNull();
                    assertThat(meta.getPurl()).isEqualTo("pkg:maven/acme/example@1.0.0?type=jar");
                    assertThat(meta.getId()).isGreaterThan(0L);
                    assertThat(meta.getMd5()).isNull();
                    assertThat(meta.getSha1()).isNull();
                    assertThat(meta.getSha256()).isNull();
                    assertThat(meta.getLastFetch()).isNull();
                    assertThat(meta.getPublishedAt()).isNull();
                }
        );
    }
}
