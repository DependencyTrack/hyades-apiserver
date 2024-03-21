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
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.junit.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class IntegrityMetaQueryManagerTest extends PersistenceCapableTest {

    @Test
    public void testGetIntegrityMetaComponent() {
        var integrityMeta = new IntegrityMetaComponent();
        integrityMeta.setPurl("pkg:maven/acme/example@1.0.0?type=jar");
        integrityMeta.setStatus(FetchStatus.IN_PROGRESS);
        integrityMeta.setLastFetch(Date.from(Instant.now().minus(2, ChronoUnit.HOURS)));

        var result = qm.getIntegrityMetaComponent("pkg:maven/acme/example@1.0.0?type=jar");
        assertThat(result).isNull();

        result = qm.persist(integrityMeta);
        assertThat(qm.getIntegrityMetaComponent(result.getPurl())).satisfies(
                meta -> {
                    assertThat(meta.getStatus()).isEqualTo(FetchStatus.IN_PROGRESS);
                    assertThat(meta.getMd5()).isNull();
                    assertThat(meta.getSha1()).isNull();
                    assertThat(meta.getSha256()).isNull();
                    assertThat(meta.getLastFetch()).isBefore(Date.from(Instant.now().minus(2, ChronoUnit.HOURS)));
                    assertThat(meta.getPublishedAt()).isNull();
                }
        );
    }

    @Test
    public void testUpdateIntegrityMetaComponent() {
        var integrityMeta = new IntegrityMetaComponent();
        integrityMeta.setPurl("pkg:maven/acme/example@1.0.0?type=jar");
        integrityMeta.setStatus(FetchStatus.IN_PROGRESS);
        integrityMeta.setLastFetch(Date.from(Instant.now().minus(2, ChronoUnit.MINUTES)));

        var result  = qm.updateIntegrityMetaComponent(integrityMeta);
        assertThat(result).isNull();

        var persisted = qm.persist(integrityMeta);
        persisted.setStatus(FetchStatus.PROCESSED);
        result  = qm.updateIntegrityMetaComponent(persisted);
        assertThat(result.getStatus()).isEqualTo(FetchStatus.PROCESSED);
    }

    @Test
    public void testGetIntegrityMetaComponentCount() {
        var integrityMeta = new IntegrityMetaComponent();
        integrityMeta.setPurl("pkg:maven/acme/example@1.0.0?type=jar");
        integrityMeta.setStatus(FetchStatus.IN_PROGRESS);
        qm.persist(integrityMeta);

        integrityMeta = new IntegrityMetaComponent();
        integrityMeta.setPurl("pkg:npm/acme/example@2.0.0");
        integrityMeta.setStatus(FetchStatus.PROCESSED);
        qm.persist(integrityMeta);

        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(2);
    }
}
