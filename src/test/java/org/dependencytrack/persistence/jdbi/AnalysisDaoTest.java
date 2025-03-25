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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Vulnerability;
import org.jdbi.v3.core.Handle;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

public class AnalysisDaoTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private AnalysisDao analysisDao;

    @Before
    public void before() throws Exception {
        super.before();
        jdbiHandle = openJdbiHandle();
        analysisDao = jdbiHandle.attach(AnalysisDao.class);
    }

    @After
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
        super.after();
    }

    @Test
    public void testGetSuppressedCount() {
        final var project = qm.createProject("acme-app", "Description 1", "1.0.0", null, null, null, null, false);

        final var c1 = new Component();
        c1.setProject(project);
        c1.setName("acme-lib");
        c1.setVersion("2.0.0");
        qm.persist(c1);

        final var c2 = new Component();
        c2.setProject(project);
        c2.setName("acme-lib");
        c2.setVersion("2.0.0");
        qm.persist(c2);

        final var vuln1 = new Vulnerability();
        vuln1.setVulnId("INT-123");
        vuln1.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vuln1);

        final var vuln2 = new Vulnerability();
        vuln2.setVulnId("INT-456");
        vuln2.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vuln2);

        qm.makeAnalysis(c1, vuln1, AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE,
                AnalysisResponse.WORKAROUND_AVAILABLE, "analysisDetails", true);
        qm.makeAnalysis(c1, vuln2, AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE,
                AnalysisResponse.WORKAROUND_AVAILABLE, "analysisDetails", true);
        qm.makeAnalysis(c2, vuln1, AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE,
                AnalysisResponse.WORKAROUND_AVAILABLE, "analysisDetails", false);
        qm.makeAnalysis(c2, vuln2, AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE,
                AnalysisResponse.WORKAROUND_AVAILABLE, "analysisDetails", true);

        assertThat(analysisDao.getSuppressedCount(c1.getId())).isEqualTo(2);
        assertThat(analysisDao.getSuppressedCount(c2.getId())).isEqualTo(1);
        assertThat(analysisDao.getSuppressedCount(project.getId(), c1.getId())).isEqualTo(2);
        assertThat(analysisDao.getSuppressedCount(project.getId(), c2.getId())).isEqualTo(1);
    }
}