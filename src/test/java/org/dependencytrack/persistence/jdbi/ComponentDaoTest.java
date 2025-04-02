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
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.IntegrityAnalysis;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.jdbi.v3.core.Handle;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.jdo.JDOObjectNotFoundException;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

public class ComponentDaoTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private ComponentDao componentDao;

    @Before
    public void before() throws Exception {
        super.before();
        jdbiHandle = openJdbiHandle();
        componentDao = jdbiHandle.attach(ComponentDao.class);
    }

    @After
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
        super.after();
    }

    @Test
    public void testCascadeDeleteComponent() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("2.0.0");
        qm.persist(component);

        // Assign a vulnerability and an accompanying analysis with comments to component.
        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vuln);
        qm.addVulnerability(vuln, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        var analysisDao = jdbiHandle.attach(AnalysisDao.class);
        analysisDao.makeAnalysis(project.getId(), component.getId(), vuln.getId(), AnalysisState.NOT_AFFECTED,
                        AnalysisJustification.CODE_NOT_REACHABLE, AnalysisResponse.WORKAROUND_AVAILABLE,
                        "analysisDetails", false);

        final Analysis analysis = qm.getAnalysis(component, vuln);
        analysisDao.makeAnalysisComment(analysis.getId(), "someComment", "someCommenter");

        // Create a child component to validate that deletion is indeed recursive.
        final var componentChild = new Component();
        componentChild.setProject(project);
        componentChild.setParent(component);
        componentChild.setName("acme-sub-lib");
        componentChild.setVersion("3.0.0");
        qm.persist(componentChild);

        // Assign a policy violation and an accompanying analysis with comments to componentChild.
        final var policy = new Policy();
        policy.setName("Test Policy");
        policy.setViolationState(Policy.ViolationState.WARN);
        policy.setOperator(Policy.Operator.ALL);
        qm.persist(policy);
        final var policyCondition = new PolicyCondition();
        policyCondition.setPolicy(policy);
        policyCondition.setSubject(PolicyCondition.Subject.COORDINATES);
        policyCondition.setOperator(PolicyCondition.Operator.MATCHES);
        policyCondition.setValue("someValue");
        qm.persist(policyCondition);
        final var policyViolation = new PolicyViolation();
        policyViolation.setPolicyCondition(policyCondition);
        policyViolation.setComponent(componentChild);
        policyViolation.setType(PolicyViolation.Type.OPERATIONAL);
        policyViolation.setTimestamp(new Date());
        qm.persist(policyViolation);
        final ViolationAnalysis violationAnalysis = qm.makeViolationAnalysis(componentChild, policyViolation,
                ViolationAnalysisState.REJECTED, false);
        qm.makeViolationAnalysisComment(violationAnalysis, "someComment", "someCommenter");

        // Assign am integrity analysis to componentChild
        final var integrityAnalysis = new IntegrityAnalysis();
        integrityAnalysis.setComponent(componentChild);
        integrityAnalysis.setMd5HashMatchStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        integrityAnalysis.setSha1HashMatchStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        integrityAnalysis.setSha256HashMatchStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        integrityAnalysis.setSha512HashMatchStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        integrityAnalysis.setIntegrityCheckStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        integrityAnalysis.setUpdatedAt(new Date());
        qm.persist(integrityAnalysis);

        // Create metrics for component.
        final var metrics = new DependencyMetrics();
        metrics.setProject(project);
        metrics.setComponent(component);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(new Date());
        qm.persist(metrics);

        componentDao.deleteComponent(component.getUuid());

        // Ensure everything has been deleted as expected.
        assertThat(qm.getAllComponents(project)).isEmpty();
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Component.class, component.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Component.class, componentChild.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(DependencyMetrics.class, metrics.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(PolicyViolation.class, policyViolation.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(IntegrityAnalysis.class, integrityAnalysis.getId()));

        // Ensure associated objects were NOT deleted.
        assertThatNoException().isThrownBy(() -> qm.getObjectById(Project.class, project.getId()));
        assertThatNoException().isThrownBy(() -> qm.getObjectById(Vulnerability.class, vuln.getId()));
        assertThatNoException().isThrownBy(() -> qm.getObjectById(PolicyCondition.class, policyCondition.getId()));
        assertThatNoException().isThrownBy(() -> qm.getObjectById(Policy.class, policy.getId()));
    }

    @Test
    public void testGetComponentId() {
        final var project = qm.createProject("acme-app", "Description 1", "1.0.0", null, null, null, null, false);
        final var component = new Component();
        component.setName("acme-lib");
        component.setVersion("2.0.0");
        component.setProject(project);
        assertThat(componentDao.getComponentId(component.getUuid())).isEqualTo(null);
        qm.persist(component);
        assertThat(componentDao.getComponentId(component.getUuid())).isEqualTo(component.getId());
    }
}