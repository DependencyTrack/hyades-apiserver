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
import org.dependencytrack.model.Epss;
import org.junit.Test;

import java.math.BigDecimal;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class EpssQueryManagerTest extends PersistenceCapableTest {

    @Test
    public void testGetEpssByCveId() {
        Epss epss = new Epss();
        epss.setCve("CVE-000");
        epss.setScore(BigDecimal.valueOf(0.01));
        epss.setPercentile(BigDecimal.valueOf(0.02));
        qm.persist(epss);

        assertThat(qm.getEpssByCveId("CVE-000")).satisfies(
                epssRecord -> {
                    assertThat(epssRecord.getScore()).isEqualByComparingTo("0.01");
                    assertThat(epssRecord.getPercentile()).isEqualByComparingTo("0.02");
                }
        );
    }

    @Test
    public void testShouldReturnNullIfEpssDoesNotExist() {
        assertThat(qm.getEpssByCveId("CVE-999")).isNull();
    }

    @Test
    public void testExistingEpssIsSynchronized() {
        Epss epss = new Epss();
        epss.setCve("CVE-000");
        epss.setScore(BigDecimal.valueOf(0.01));
        epss.setPercentile(BigDecimal.valueOf(0.02));
        qm.persist(epss);

        Epss epssNew = new Epss();
        epssNew.setCve("CVE-000");
        epssNew.setScore(BigDecimal.valueOf(0.01));
        epssNew.setPercentile(BigDecimal.valueOf(1.02));
        qm.synchronizeEpss(epssNew);

        assertThat(qm.getEpssByCveId("CVE-000")).satisfies(
                epssSynchronized -> {
                    assertThat(epssSynchronized.getScore()).isEqualByComparingTo("0.01");
                    assertThat(epssSynchronized.getPercentile()).isEqualByComparingTo("1.02");
                }
        );
    }

    @Test
    public void testNewEpssIsSynchronized() {
        Epss epss = new Epss();
        epss.setCve("CVE-000");
        epss.setScore(BigDecimal.valueOf(0.01));
        epss.setPercentile(BigDecimal.valueOf(0.02));
        qm.synchronizeEpss(epss);
        assertThat(qm.getEpssByCveId("CVE-000")).satisfies(
                epssSynchronized -> {
                    assertThat(epssSynchronized.getScore()).isEqualByComparingTo("0.01");
                    assertThat(epssSynchronized.getPercentile()).isEqualByComparingTo("0.02");
                }
        );
    }

    @Test
    public void testGetEpssForCveIds() {
        Epss epss1 = new Epss();
        epss1.setCve("CVE-000");
        epss1.setScore(BigDecimal.valueOf(0.01));
        epss1.setPercentile(BigDecimal.valueOf(0.02));
        Epss epss2 = new Epss();
        epss2.setCve("CVE-999");
        epss2.setScore(BigDecimal.valueOf(0.08));
        epss2.setPercentile(BigDecimal.valueOf(0.09));
        qm.persist(List.of(epss1, epss2));

        assertThat(qm.getEpssForCveIds(List.of("CVE-000", "CVE-999"))).satisfies(
                epssRecords -> {
                    var value = epssRecords.get("CVE-000");
                    assertThat(value.getScore()).isEqualByComparingTo("0.01");
                    assertThat(value.getPercentile()).isEqualByComparingTo("0.02");
                    value = epssRecords.get("CVE-999");
                    assertThat(value.getScore()).isEqualByComparingTo("0.08");
                    assertThat(value.getPercentile()).isEqualByComparingTo("0.09");
                }
        );
    }
}
