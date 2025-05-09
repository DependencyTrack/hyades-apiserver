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

import alpine.notification.NotificationLevel;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.IntegrityAnalysis;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Vex;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationScope;
import org.jdbi.v3.core.Handle;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.jdo.JDOObjectNotFoundException;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class ProjectDaoTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private ProjectDao projectDao;

    @Before
    public void before() throws Exception {
        super.before();
        jdbiHandle = openJdbiHandle();
        projectDao = jdbiHandle.attach(ProjectDao.class);
    }

    @After
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
        super.after();
    }

    @Test
    public void testCascadeDeleteProject() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var author = new OrganizationalContact();
        author.setName("authorName");
        final var projectMetadata = new ProjectMetadata();
        projectMetadata.setProject(project);
        projectMetadata.setAuthors(List.of(author));
        qm.persist(projectMetadata);

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
        withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                .makeAnalysis(project.getId(), component.getId(), vuln.getId(), AnalysisState.NOT_AFFECTED,
                        AnalysisJustification.CODE_NOT_REACHABLE, AnalysisResponse.WORKAROUND_AVAILABLE,
                        "analysisDetails", false));
        final Analysis analysis = qm.getAnalysis(component, vuln);
        withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                .makeAnalysisComment(analysis.getId(), "someComment", "someCommenter"));

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
        policy.setProjects(List.of(project));
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
        final var componentMetrics = new DependencyMetrics();
        componentMetrics.setProject(project);
        componentMetrics.setComponent(component);
        componentMetrics.setFirstOccurrence(new Date());
        componentMetrics.setLastOccurrence(new Date());
        qm.persist(componentMetrics);

        // Create metrics for project.
        final var projectMetrics = new ProjectMetrics();
        projectMetrics.setProject(project);
        projectMetrics.setFirstOccurrence(new Date());
        projectMetrics.setLastOccurrence(new Date());
        qm.persist(projectMetrics);

        // Create a BOM.
        final Bom bom = qm.createBom(project, new Date(), Bom.Format.CYCLONEDX, "1.4", 1, "serialNumber", UUID.randomUUID(), null);

        // Create a child project with an accompanying component.
        final var projectChild = new Project();
        projectChild.setParent(project);
        projectChild.setName("acme-sub-app");
        projectChild.setVersion("1.1.0");
        qm.persist(projectChild);
        final var projectChildComponent = new Component();
        projectChildComponent.setProject(projectChild);
        projectChildComponent.setName("acme-lib-x");
        projectChildComponent.setVersion("4.0.0");
        qm.persist(projectChildComponent);

        // Create a VEX for projectChild.
        final Vex vex = qm.createVex(projectChild, new Date(), Vex.Format.CYCLONEDX, "1.3", 1, "serialNumber");

        // Create a notification rule and associate projectChild with it.
        final NotificationPublisher notificationPublisher = qm.createNotificationPublisher("name", "description", "publisherClass", "templateContent", "templateMimeType", true);
        final NotificationRule notificationRule = qm.createNotificationRule("name", NotificationScope.PORTFOLIO, NotificationLevel.WARNING, notificationPublisher);
        notificationRule.getProjects().add(projectChild);
        qm.persist(notificationRule);

        final var serviceComponent = new ServiceComponent();
        serviceComponent.setName("service-component");
        serviceComponent.setProject(project);
        qm.persist(serviceComponent);

        projectDao.deleteProject(project.getUuid());

        // Ensure everything has been deleted as expected.
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Project.class, project.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Project.class, projectChild.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Component.class, component.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Component.class, componentChild.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Component.class, projectChildComponent.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(ProjectMetrics.class, projectMetrics.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(ProjectMetadata.class, projectMetadata.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(DependencyMetrics.class, componentMetrics.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(IntegrityAnalysis.class, integrityAnalysis.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Bom.class, bom.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Vex.class, vex.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(ServiceComponent.class, serviceComponent.getId()));

        // Ensure associated objects were NOT deleted.
        assertThatNoException().isThrownBy(() -> qm.getObjectById(Vulnerability.class, vuln.getId()));
        assertThatNoException().isThrownBy(() -> qm.getObjectById(PolicyCondition.class, policyCondition.getId()));
        assertThatNoException().isThrownBy(() -> qm.getObjectById(Policy.class, policy.getId()));
        assertThatNoException().isThrownBy(() -> qm.getObjectById(NotificationRule.class, notificationRule.getId()));
        assertThatNoException().isThrownBy(() -> qm.getObjectById(NotificationPublisher.class, notificationPublisher.getId()));

        // Ensure that associations have been cleaned up.
        qm.getPersistenceManager().refresh(notificationRule);
        assertThat(notificationRule.getProjects()).isEmpty();
        qm.getPersistenceManager().refresh(policy);
        assertThat(policy.getProjects()).isEmpty();
    }

    @Test
    public void testGetProjectId() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        assertThat(projectDao.getProjectId(project.getUuid())).isEqualTo(null);
        qm.persist(project);
        assertThat(projectDao.getProjectId(project.getUuid())).isEqualTo(project.getId());
    }
}