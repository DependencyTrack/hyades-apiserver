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
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.jdbi.v3.core.Handle;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.Vulnerability.Source.NVD;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

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
    public void testGetAnalysis() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        qm.createVulnerability(vulnerability, false);

        analysisDao.makeAnalysis(project.getId(), component.getId(), vulnerability.getId(), AnalysisState.NOT_AFFECTED, AnalysisJustification.PROTECTED_AT_RUNTIME, AnalysisResponse.UPDATE, "Analysis details here", true);
        var analysis = analysisDao.getAnalysis(component.getId(), vulnerability.getId());

        assertThat(analysis).isNotNull();
        assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(analysis.getAnalysisJustification()).isEqualTo(AnalysisJustification.PROTECTED_AT_RUNTIME);
        assertThat(analysis.getAnalysisResponse()).isEqualTo(AnalysisResponse.UPDATE);
        assertThat(analysis.getAnalysisDetails()).isEqualTo("Analysis details here");
        assertThat(analysis.isSuppressed()).isTrue();
    }

    @Test
    public void testMakeAnalysisComment() {
        final var project = qm.createProject("acme-app", "Description 1", "1.0.0", null, null, null, null, false);

        final var c1 = new Component();
        c1.setProject(project);
        c1.setName("acme-lib");
        c1.setVersion("2.0.0");
        qm.persist(c1);

        final var vuln1 = new Vulnerability();
        vuln1.setVulnId("INT-123");
        vuln1.setSource(NVD);
        qm.persist(vuln1);

        final var analysis = analysisDao.makeAnalysis(project.getId(), c1.getId(), vuln1.getId(), AnalysisState.NOT_AFFECTED, null, null, null, true);

        assertThat(analysisDao.makeAnalysisComment(analysis.getId(), null, "tester")).isNull();

        var analysisComment = analysisDao.makeAnalysisComment(analysis.getId(), "test-comment", "tester");

        assertThat(analysisComment).isNotNull();
        assertThat(analysisComment.getComment()).isEqualTo("test-comment");
        assertThat(analysisComment.getCommenter()).isEqualTo("tester");
        assertThat(analysisComment.getTimestamp()).isNotNull();
    }

    @Test
    public void testMakeAnalysisNonExisting() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        qm.createVulnerability(vulnerability, false);

        withJdbiHandle(handle -> analysisDao.makeAnalysis(project.getId(), component.getId(), vulnerability.getId(), null,
                        AnalysisJustification.CODE_NOT_REACHABLE, AnalysisResponse.WILL_NOT_FIX, "Analysis details here", true));
        assertThat(qm.getAnalysis(component, vulnerability)).satisfies(analysis -> {
            assertThat(analysis.getVulnerability()).isEqualTo(vulnerability);
            assertThat(analysis.getComponent()).isEqualTo(component);
            assertThat(analysis.getProject()).isEqualTo(project);
            assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_SET);
            assertThat(analysis.getAnalysisJustification()).isEqualTo(AnalysisJustification.CODE_NOT_REACHABLE);
            assertThat(analysis.getAnalysisResponse()).isEqualTo(AnalysisResponse.WILL_NOT_FIX);
            assertThat(analysis.getAnalysisDetails()).isEqualTo("Analysis details here");
            assertThat(analysis.isSuppressed()).isTrue();
        });
    }

    @Test
    public void testMakeAnalysisExisting() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        qm.createVulnerability(vulnerability, false);

        var analysisExisting = analysisDao.makeAnalysis(project.getId(), component.getId(), vulnerability.getId(), AnalysisState.NOT_AFFECTED, null, null, null, true);

        var analysisUpdated = analysisDao.makeAnalysis(project.getId(), component.getId(), vulnerability.getId(), AnalysisState.NOT_AFFECTED,
                        AnalysisJustification.CODE_NOT_REACHABLE, AnalysisResponse.WILL_NOT_FIX, "Analysis details here", false);

        assertThat(analysisUpdated.getId()).isEqualTo(analysisExisting.getId());
        assertThat(analysisUpdated.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(analysisUpdated.getAnalysisJustification()).isEqualTo(AnalysisJustification.CODE_NOT_REACHABLE);
        assertThat(analysisUpdated.getAnalysisResponse()).isEqualTo(AnalysisResponse.WILL_NOT_FIX);
        assertThat(analysisUpdated.getAnalysisDetails()).isEqualTo("Analysis details here");
        assertThat(analysisUpdated.isSuppressed()).isFalse();
    }

    @Test
    public void testMakeAnalysisExistingByNullValues() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        qm.createVulnerability(vulnerability, false);

        var analysisExisting = analysisDao.makeAnalysis(project.getId(), component.getId(), vulnerability.getId(), AnalysisState.NOT_AFFECTED,
                        AnalysisJustification.CODE_NOT_REACHABLE, AnalysisResponse.WILL_NOT_FIX, "Analysis details here", true);

        var analysisUpdated = analysisDao.makeAnalysis(project.getId(), component.getId(), vulnerability.getId(), null, null, null, null, null);

        assertThat(analysisUpdated.getId()).isEqualTo(analysisExisting.getId());
        assertThat(analysisUpdated.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(analysisUpdated.getAnalysisJustification()).isEqualTo(AnalysisJustification.CODE_NOT_REACHABLE);
        assertThat(analysisUpdated.getAnalysisResponse()).isEqualTo(AnalysisResponse.WILL_NOT_FIX);
        assertThat(analysisUpdated.getAnalysisDetails()).isEqualTo("Analysis details here");
        assertThat(analysisUpdated.isSuppressed()).isTrue();
    }

    @Test
    public void testGetAnalysisComments() {
        final var project = qm.createProject("acme-app", "Description 1", "1.0.0", null, null, null, null, false);

        final var c1 = new Component();
        c1.setProject(project);
        c1.setName("acme-lib");
        c1.setVersion("2.0.0");
        qm.persist(c1);

        final var vuln1 = new Vulnerability();
        vuln1.setVulnId("INT-123");
        vuln1.setSource(NVD);
        qm.persist(vuln1);

        final var analysis = analysisDao.makeAnalysis(project.getId(), c1.getId(), vuln1.getId(), null, null, null, null, true);

        assertThat(analysisDao.makeAnalysisComment(analysis.getId(), null, "tester")).isNull();

        analysisDao.makeAnalysisComment(analysis.getId(), "test-comment-1", "tester");
        analysisDao.makeAnalysisComment(analysis.getId(), "test-comment-2", "tester");
        analysisDao.makeAnalysisComment(analysis.getId(), "test-comment-3", "tester");

        var comments = analysisDao.getComments(analysis.getId());
        assertThat(comments).satisfiesExactly(comment -> {
            assertThat(comment.getComment()).isEqualTo("test-comment-1");
        }, comment -> {
            assertThat(comment.getComment()).isEqualTo("test-comment-2");
        }, comment -> {
            assertThat(comment.getComment()).isEqualTo("test-comment-3");
        });
    }
}