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

import com.google.protobuf.util.JsonFormat;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.notification.proto.v1.ComponentVulnAnalysisCompleteSubject;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerableDependencySubject;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.query.GetProjectAuditChangeNotificationSubjectQuery;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.hamcrest.Matchers.equalTo;

public class NotificationSubjectDaoTest extends PersistenceCapableTest {

    @Test
    public void testGetForNewVulnerabilities() {
        final var project = new Project();
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setDescription("projectDescription");
        project.setPurl("projectPurl");
        qm.persist(project);
        qm.bind(project, List.of(
                qm.createTag("projectTagA"),
                qm.createTag("projectTagB")
        ));

        final var component = new Component();
        component.setProject(project);
        component.setGroup("componentGroup");
        component.setName("componentName");
        component.setVersion("componentVersion");
        component.setPurl("componentPurl");
        component.setMd5("componentMd5");
        component.setSha1("componentSha1");
        component.setSha256("componentSha256");
        component.setSha512("componentSha512");
        qm.persist(component);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("CVE-100");
        vulnA.setSource(Vulnerability.Source.NVD);
        vulnA.setTitle("vulnATitle");
        vulnA.setSubTitle("vulnASubTitle");
        vulnA.setDescription("vulnADescription");
        vulnA.setRecommendation("vulnARecommendation");
        vulnA.setSeverity(Severity.LOW);
        vulnA.setCvssV2BaseScore(BigDecimal.valueOf(1.1));
        vulnA.setCvssV3BaseScore(BigDecimal.valueOf(2.2));
        vulnA.setCvssV2Vector("(AV:N/AC:M/Au:S/C:P/I:P/A:P)");
        vulnA.setCvssV3Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
        vulnA.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.3));
        vulnA.setOwaspRRLikelihoodScore(BigDecimal.valueOf(4.4));
        vulnA.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(5.5));
        vulnA.setOwaspRRVector("(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)");
        vulnA.setCwes(List.of(666, 777));
        qm.persist(vulnA);

        final var vulnB = new Vulnerability();
        vulnB.setVulnId("CVE-200");
        vulnB.setSource(Vulnerability.Source.NVD);
        qm.persist(vulnB);

        useJdbiTransaction(handle -> new VulnerabilityAliasDao(handle)
                .syncAssertions("TEST", new VulnerabilityKey("CVE-100", Vulnerability.Source.NVD),
                        Set.of(new VulnerabilityKey("GHSA-100", Vulnerability.Source.GITHUB))));

        qm.addVulnerability(vulnA, component, "internal");
        qm.addVulnerability(vulnB, component, "internal");

        // Suppress vulnB, it should not appear in the query results.
        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vulnB)
                        .withState(AnalysisState.FALSE_POSITIVE)
                        .withSuppress(true));

        final List<NewVulnerabilitySubject> subjects = withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                .getForNewVulnerabilities(
                        List.of(component.getId(), component.getId()), List.of(vulnA.getId(), vulnB.getId())));

        assertThat(subjects).satisfiesExactly(subject ->
                assertThatJson(JsonFormat.printer().print(subject))
                        .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                        .withMatcher("componentUuid", equalTo(component.getUuid().toString()))
                        .withMatcher("vulnUuid", equalTo(vulnA.getUuid().toString()))
                        .isEqualTo("""
                                {
                                  "affectedProjects": [
                                    {
                                      "description": "projectDescription",
                                      "name": "projectName",
                                      "purl": "projectPurl",
                                      "isActive":true,
                                      "tags": [
                                        "projecttaga",
                                        "projecttagb"
                                      ],
                                      "uuid": "${json-unit.matches:projectUuid}",
                                      "version": "projectVersion"
                                    }
                                  ],
                                  "component": {
                                    "group": "componentGroup",
                                    "md5": "componentmd5",
                                    "name": "componentName",
                                    "purl": "componentPurl",
                                    "sha1": "componentsha1",
                                    "sha256": "componentsha256",
                                    "sha512": "componentsha512",
                                    "uuid": "${json-unit.matches:componentUuid}",
                                    "version": "componentVersion"
                                  },
                                  "project": {
                                    "description": "projectDescription",
                                    "name": "projectName",
                                    "purl": "projectPurl",
                                    "isActive":true,
                                    "tags": [
                                      "projecttaga",
                                      "projecttagb"
                                    ],
                                    "uuid": "${json-unit.matches:projectUuid}",
                                    "version": "projectVersion"
                                  },
                                  "vulnerability": {
                                    "aliases": [
                                      {"vulnId": "GHSA-100", "source": "GITHUB"}
                                    ],
                                    "cvssv2": 1.1,
                                    "cvssv3": 2.2,
                                    "cwes": [
                                      {
                                        "cweId": 666,
                                        "name": "Operation on Resource in Wrong Phase of Lifetime"
                                      },
                                      {
                                        "cweId": 777,
                                        "name": "Regular Expression without Anchors"
                                      }
                                    ],
                                    "description": "vulnADescription",
                                    "owaspRRBusinessImpact": 3.3,
                                    "owaspRRLikelihood": 4.4,
                                    "owaspRRTechnicalImpact": 5.5,
                                    "recommendation": "vulnARecommendation",
                                    "severity": "LOW",
                                    "source": "NVD",
                                    "subtitle": "vulnASubTitle",
                                    "title": "vulnATitle",
                                    "uuid": "${json-unit.matches:vulnUuid}",
                                    "vulnId": "CVE-100",
                                    "cvssV2Vector": "(AV:N/AC:M/Au:S/C:P/I:P/A:P)",
                                    "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                    "owaspRRVector": "(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)"
                                  }
                                }
                                """));
    }

    @Test
    public void testGetForNewVulnerabilityWithAnalysisRatingOverwrite() throws Exception {
        final var project = new Project();
        project.setName("projectName");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("componentName");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-100");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.MEDIUM);
        vuln.setCvssV2Vector("");
        vuln.setCvssV2BaseScore(BigDecimal.valueOf(1.1));
        vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(1.2));
        vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(1.3));
        vuln.setCvssV3Vector("cvssV3Vector");
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(2.1));
        vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(2.2));
        vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(2.3));
        vuln.setOwaspRRVector("owaspRrVector");
        vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.1));
        vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(3.2));
        vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(3.3));
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, "internal");

        final var analysis = new Analysis();
        analysis.setComponent(component);
        analysis.setVulnerability(vuln);
        analysis.setAnalysisState(AnalysisState.EXPLOITABLE);
        analysis.setSeverity(Severity.CRITICAL);
        analysis.setCvssV3Vector("cvssV3VectorOverwrite");
        analysis.setCvssV3Score(BigDecimal.valueOf(10.0));
        qm.persist(analysis);

        final List<NewVulnerabilitySubject> subjects = withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                .getForNewVulnerabilities(List.of(component.getId()), List.of(vuln.getId())));

        assertThat(subjects).hasSize(1);
        assertThatJson(JsonFormat.printer().print(subjects.getFirst()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("componentUuid", equalTo(component.getUuid().toString()))
                .withMatcher("vulnUuid", equalTo(vuln.getUuid().toString()))
                .isEqualTo("""
                        {
                          "component": {
                            "uuid": "${json-unit.matches:componentUuid}",
                            "name": "componentName"
                          },
                          "project": {
                            "uuid": "${json-unit.matches:projectUuid}",
                            "name": "projectName",
                            "isActive":true
                          },
                          "vulnerability": {
                            "uuid": "${json-unit.matches:vulnUuid}",
                            "vulnId": "CVE-100",
                            "source": "NVD",
                            "cvssv3": 10.0,
                            "severity": "CRITICAL",
                            "cvssV3Vector": "cvssV3VectorOverwrite"
                          },
                          "affectedProjects": [
                            {
                              "uuid": "${json-unit.matches:projectUuid}",
                              "name": "projectName",
                              "isActive":true
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void testGetForNewVulnerableDependency() throws Exception {
        final var project = new Project();
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setDescription("projectDescription");
        project.setPurl("projectPurl");
        qm.persist(project);
        qm.bind(project, List.of(
                qm.createTag("projectTagA"),
                qm.createTag("projectTagB")
        ));

        final var component = new Component();
        component.setProject(project);
        component.setGroup("componentGroup");
        component.setName("componentName");
        component.setVersion("componentVersion");
        component.setPurl("componentPurl");
        component.setMd5("componentMd5");
        component.setSha1("componentSha1");
        component.setSha256("componentSha256");
        component.setSha512("componentSha512");
        qm.persist(component);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("CVE-100");
        vulnA.setSource(Vulnerability.Source.NVD);
        vulnA.setTitle("vulnATitle");
        vulnA.setSubTitle("vulnASubTitle");
        vulnA.setDescription("vulnADescription");
        vulnA.setRecommendation("vulnARecommendation");
        vulnA.setSeverity(Severity.LOW);
        vulnA.setCvssV2BaseScore(BigDecimal.valueOf(1.1));
        vulnA.setCvssV3BaseScore(BigDecimal.valueOf(2.2));
        vulnA.setCvssV2Vector("(AV:N/AC:M/Au:S/C:P/I:P/A:P)");
        vulnA.setCvssV3Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
        vulnA.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.3));
        vulnA.setOwaspRRLikelihoodScore(BigDecimal.valueOf(4.4));
        vulnA.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(5.5));
        vulnA.setOwaspRRVector("(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)");
        vulnA.setCwes(List.of(666, 777));
        qm.persist(vulnA);

        final var vulnB = new Vulnerability();
        vulnB.setVulnId("CVE-200");
        vulnB.setSource(Vulnerability.Source.NVD);
        qm.persist(vulnB);

        useJdbiTransaction(handle -> new VulnerabilityAliasDao(handle)
                .syncAssertions(
                        "TEST",
                        new VulnerabilityKey("CVE-100", Vulnerability.Source.NVD),
                        Set.of(new VulnerabilityKey("GHSA-100", Vulnerability.Source.GITHUB))));

        qm.addVulnerability(vulnA, component, "internal");
        qm.addVulnerability(vulnB, component, "internal");

        // Suppress vulnB, it should not appear in the query results.
        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vulnB)
                        .withState(AnalysisState.FALSE_POSITIVE)
                        .withSuppress(true));

        final List<NewVulnerableDependencySubject> subjects = withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                .getForNewVulnerableDependencies(List.of(component.getId())));

        assertThat(subjects).hasSize(1);
        assertThatJson(JsonFormat.printer().print(subjects.getFirst()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("componentUuid", equalTo(component.getUuid().toString()))
                .withMatcher("vulnUuid", equalTo(vulnA.getUuid().toString()))
                .isEqualTo("""
                        {
                          "component": {
                            "uuid": "${json-unit.matches:componentUuid}",
                            "group": "componentGroup",
                            "name": "componentName",
                            "version": "componentVersion",
                            "purl": "componentPurl",
                            "md5": "componentmd5",
                            "sha1": "componentsha1",
                            "sha256": "componentsha256",
                            "sha512": "componentsha512"
                          },
                          "project": {
                            "uuid": "${json-unit.matches:projectUuid}",
                            "name": "projectName",
                            "version": "projectVersion",
                            "description": "projectDescription",
                            "purl": "projectPurl",
                            "isActive":true,
                            "tags": [
                              "projecttaga",
                              "projecttagb"
                            ]
                          },
                          "vulnerabilities": [
                            {
                              "uuid": "${json-unit.matches:vulnUuid}",
                              "vulnId": "CVE-100",
                              "source": "NVD",
                              "title": "vulnATitle",
                              "subtitle": "vulnASubTitle",
                              "description": "vulnADescription",
                              "recommendation": "vulnARecommendation",
                              "cvssv2": 1.1,
                              "cvssv3": 2.2,
                              "owaspRRLikelihood": 4.4,
                              "owaspRRTechnicalImpact": 5.5,
                              "owaspRRBusinessImpact": 3.3,
                              "severity": "LOW",
                              "cwes": [
                                {
                                  "cweId": 666,
                                  "name": "Operation on Resource in Wrong Phase of Lifetime"
                                },
                                {
                                  "cweId": 777,
                                  "name": "Regular Expression without Anchors"
                                }
                              ],
                              "cvssV2Vector": "(AV:N/AC:M/Au:S/C:P/I:P/A:P)",
                              "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                              "owaspRRVector": "(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)",
                              "aliases": [
                                {"vulnId": "GHSA-100", "source": "GITHUB"}
                              ]
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void testGetForNewVulnerableDependencyWithAnalysisRatingOverwrite() throws Exception {
        final var project = new Project();
        project.setName("projectName");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("componentName");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-100");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.MEDIUM);
        vuln.setCvssV2Vector("");
        vuln.setCvssV2BaseScore(BigDecimal.valueOf(1.1));
        vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(1.2));
        vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(1.3));
        vuln.setCvssV3Vector("cvssV3Vector");
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(2.1));
        vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(2.2));
        vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(2.3));
        vuln.setOwaspRRVector("owaspRrVector");
        vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.1));
        vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(3.2));
        vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(3.3));
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, "internal");

        final var analysis = new Analysis();
        analysis.setComponent(component);
        analysis.setVulnerability(vuln);
        analysis.setAnalysisState(AnalysisState.EXPLOITABLE);
        analysis.setSeverity(Severity.CRITICAL);
        analysis.setCvssV3Vector("cvssV3VectorOverwrite");
        analysis.setCvssV3Score(BigDecimal.valueOf(10.0));
        qm.persist(analysis);

        final List<NewVulnerableDependencySubject> subjects = withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                .getForNewVulnerableDependencies(List.of(component.getId())));

        assertThat(subjects).hasSize(1);
        assertThatJson(JsonFormat.printer().print(subjects.getFirst()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("componentUuid", equalTo(component.getUuid().toString()))
                .withMatcher("vulnUuid", equalTo(vuln.getUuid().toString()))
                .isEqualTo("""
                        {
                          "component": {
                            "uuid": "${json-unit.matches:componentUuid}",
                            "name": "componentName"
                          },
                          "project": {
                            "uuid": "${json-unit.matches:projectUuid}",
                            "name": "projectName",
                            "isActive":true
                          },
                          "vulnerabilities": [
                            {
                              "uuid": "${json-unit.matches:vulnUuid}",
                              "vulnId": "CVE-100",
                              "source": "NVD",
                              "cvssv3": 10.0,
                              "severity": "CRITICAL",
                              "cvssV3Vector": "cvssV3VectorOverwrite"
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void testGetForProjectAuditChange() {
        final var project = new Project();
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setDescription("projectDescription");
        project.setPurl("projectPurl");
        qm.persist(project);
        qm.bind(project, List.of(
                qm.createTag("projectTagA"),
                qm.createTag("projectTagB")
        ));

        final var component = new Component();
        component.setProject(project);
        component.setGroup("componentGroup");
        component.setName("componentName");
        component.setVersion("componentVersion");
        component.setPurl("componentPurl");
        component.setMd5("componentMd5");
        component.setSha1("componentSha1");
        component.setSha256("componentSha256");
        component.setSha512("componentSha512");
        qm.persist(component);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("CVE-100");
        vulnA.setSource(Vulnerability.Source.NVD);
        vulnA.setTitle("vulnATitle");
        vulnA.setSubTitle("vulnASubTitle");
        vulnA.setDescription("vulnADescription");
        vulnA.setRecommendation("vulnARecommendation");
        vulnA.setSeverity(Severity.LOW);
        vulnA.setCvssV2BaseScore(BigDecimal.valueOf(1.1));
        vulnA.setCvssV3BaseScore(BigDecimal.valueOf(2.2));
        vulnA.setCvssV2Vector("(AV:N/AC:M/Au:S/C:P/I:P/A:P)");
        vulnA.setCvssV3Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
        vulnA.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.3));
        vulnA.setOwaspRRLikelihoodScore(BigDecimal.valueOf(4.4));
        vulnA.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(5.5));
        vulnA.setOwaspRRVector("(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)");
        vulnA.setCwes(List.of(666, 777));
        qm.persist(vulnA);

        useJdbiTransaction(handle -> new VulnerabilityAliasDao(handle)
                .syncAssertions("TEST", new VulnerabilityKey("CVE-100", Vulnerability.Source.NVD),
                        Set.of(new VulnerabilityKey("GHSA-100", Vulnerability.Source.GITHUB))));

        qm.addVulnerability(vulnA, component, "internal");

        // Suppress vulnB, it should not appear in the query results.
        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vulnA)
                        .withState(AnalysisState.NOT_AFFECTED));

        var policyAnalysis = qm.getAnalysis(component, vulnA);

        final List<VulnerabilityAnalysisDecisionChangeSubject> subjects =
                withJdbiHandle(handle -> handle
                        .attach(NotificationSubjectDao.class)
                        .getForProjectAuditChanges(List.of(
                                new GetProjectAuditChangeNotificationSubjectQuery(
                                        component.getId(), vulnA.getId(), policyAnalysis.getAnalysisState(), policyAnalysis.isSuppressed()))));

        assertThat(subjects).satisfiesExactly(subject ->
                assertThatJson(JsonFormat.printer().print(subject))
                        .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                        .withMatcher("componentUuid", equalTo(component.getUuid().toString()))
                        .withMatcher("vulnUuid", equalTo(vulnA.getUuid().toString()))
                        .isEqualTo("""
                                {
                                     "component": {
                                         "uuid": "${json-unit.matches:componentUuid}",
                                         "group": "componentGroup",
                                         "name": "componentName",
                                         "version": "componentVersion",
                                         "purl": "componentPurl",
                                         "md5": "componentmd5",
                                         "sha1": "componentsha1",
                                         "sha256": "componentsha256",
                                         "sha512": "componentsha512"
                                     },
                                     "project": {
                                         "uuid": "${json-unit.matches:projectUuid}",
                                         "name": "projectName",
                                         "version": "projectVersion",
                                         "description": "projectDescription",
                                         "isActive":true,
                                         "purl": "projectPurl",
                                         "tags": [
                                             "projecttaga",
                                             "projecttagb"
                                         ]
                                     },
                                     "vulnerability": {
                                         "uuid": "${json-unit.matches:vulnUuid}",
                                         "vulnId": "CVE-100",
                                         "source": "NVD",
                                         "aliases": [
                                             {
                                                 "vulnId": "GHSA-100",
                                                 "source": "GITHUB"
                                             }
                                         ],
                                         "title": "vulnATitle",
                                         "subtitle": "vulnASubTitle",
                                         "description": "vulnADescription",
                                         "recommendation": "vulnARecommendation",
                                         "cvssv2": 1.1,
                                         "cvssv3": 2.2,
                                         "owaspRRLikelihood": 4.4,
                                         "owaspRRTechnicalImpact": 5.5,
                                         "owaspRRBusinessImpact": 3.3,
                                         "severity": "LOW",
                                         "cwes": [
                                             {
                                                 "cweId": 666,
                                                 "name": "Operation on Resource in Wrong Phase of Lifetime"
                                             },
                                             {
                                                 "cweId": 777,
                                                 "name": "Regular Expression without Anchors"
                                             }
                                         ],
                                         "cvssV2Vector": "(AV:N/AC:M/Au:S/C:P/I:P/A:P)",
                                         "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                         "owaspRRVector": "(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)"
                                     },
                                     "analysis": {
                                         "component": {
                                             "uuid": "${json-unit.matches:componentUuid}",
                                             "group": "componentGroup",
                                             "name": "componentName",
                                             "version": "componentVersion",
                                             "purl": "componentPurl",
                                             "md5": "componentmd5",
                                             "sha1": "componentsha1",
                                             "sha256": "componentsha256",
                                             "sha512": "componentsha512"
                                         },
                                         "project": {
                                             "uuid": "${json-unit.matches:projectUuid}",
                                             "name": "projectName",
                                             "version": "projectVersion",
                                             "description": "projectDescription",
                                             "purl": "projectPurl",
                                             "isActive":true,
                                             "tags": [
                                                 "projecttaga",
                                                 "projecttagb"
                                             ]
                                         },
                                         "vulnerability": {
                                             "uuid": "${json-unit.matches:vulnUuid}",
                                             "vulnId": "CVE-100",
                                             "source": "NVD",
                                             "aliases": [
                                                 {
                                                     "vulnId": "GHSA-100",
                                                     "source": "GITHUB"
                                                 }
                                             ],
                                             "title": "vulnATitle",
                                             "subtitle": "vulnASubTitle",
                                             "description": "vulnADescription",
                                             "recommendation": "vulnARecommendation",
                                             "cvssv2": 1.1,
                                             "cvssv3": 2.2,
                                             "owaspRRLikelihood": 4.4,
                                             "owaspRRTechnicalImpact": 5.5,
                                             "owaspRRBusinessImpact": 3.3,
                                             "severity": "LOW",
                                             "cwes": [
                                                 {
                                                     "cweId": 666,
                                                     "name": "Operation on Resource in Wrong Phase of Lifetime"
                                                 },
                                                 {
                                                     "cweId": 777,
                                                     "name": "Regular Expression without Anchors"
                                                 }
                                             ],
                                         "cvssV2Vector": "(AV:N/AC:M/Au:S/C:P/I:P/A:P)",
                                         "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                         "owaspRRVector": "(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)"
                                         },
                                         "state": "NOT_AFFECTED",
                                         "suppressed": false
                                     }
                                 }
                                """));
    }

    @Test
    public void testGetForProjectVulnAnalysisCompleteWithFindings() {
        final var project = new Project();
        project.setName("projectName");
        project.setVersion("projectVersion");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("componentA");
        componentA.setVersion("1.0");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("componentB");
        componentB.setVersion("2.0");
        qm.persist(componentB);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("CVE-100");
        vulnA.setSource(Vulnerability.Source.NVD);
        vulnA.setSeverity(Severity.HIGH);
        vulnA.setCvssV3BaseScore(BigDecimal.valueOf(7.5));
        qm.persist(vulnA);

        final var vulnB = new Vulnerability();
        vulnB.setVulnId("CVE-200");
        vulnB.setSource(Vulnerability.Source.NVD);
        vulnB.setSeverity(Severity.MEDIUM);
        qm.persist(vulnB);

        qm.addVulnerability(vulnA, componentA, "internal");
        qm.addVulnerability(vulnB, componentA, "internal");
        qm.addVulnerability(vulnA, componentB, "internal");

        final Map<UUID, List<ComponentVulnAnalysisCompleteSubject>> result =
                withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                        .getForProjectVulnAnalysisComplete(Set.of(project.getUuid())));

        assertThat(result).containsKey(project.getUuid());
        final List<ComponentVulnAnalysisCompleteSubject> findings = result.get(project.getUuid());
        assertThat(findings).hasSize(2);

        assertThat(findings).anySatisfy(finding -> {
            assertThat(finding.getComponent().getName()).isEqualTo("componentA");
            assertThat(finding.getVulnerabilitiesList()).hasSize(2);
            assertThat(finding.getVulnerabilitiesList())
                    .extracting(org.dependencytrack.notification.proto.v1.Vulnerability::getVulnId)
                    .containsExactlyInAnyOrder("CVE-100", "CVE-200");
        });

        assertThat(findings).anySatisfy(finding -> {
            assertThat(finding.getComponent().getName()).isEqualTo("componentB");
            assertThat(finding.getVulnerabilitiesList()).hasSize(1);
            assertThat(finding.getVulnerabilities(0).getVulnId()).isEqualTo("CVE-100");
        });
    }

    @Test
    public void testGetForProjectVulnAnalysisCompleteWithNoFindings() {
        final var project = new Project();
        project.setName("projectName");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("componentName");
        qm.persist(component);

        final Map<UUID, List<ComponentVulnAnalysisCompleteSubject>> result =
                withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                        .getForProjectVulnAnalysisComplete(Set.of(project.getUuid())));

        assertThat(result).isEmpty();
    }

    @Test
    public void testGetForProjectVulnAnalysisCompleteExcludesSuppressed() {
        final var project = new Project();
        project.setName("projectName");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("componentName");
        qm.persist(component);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("CVE-100");
        vulnA.setSource(Vulnerability.Source.NVD);
        vulnA.setSeverity(Severity.HIGH);
        qm.persist(vulnA);

        final var vulnB = new Vulnerability();
        vulnB.setVulnId("CVE-200");
        vulnB.setSource(Vulnerability.Source.NVD);
        vulnB.setSeverity(Severity.LOW);
        qm.persist(vulnB);

        qm.addVulnerability(vulnA, component, "internal");
        qm.addVulnerability(vulnB, component, "internal");

        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vulnB)
                        .withState(AnalysisState.FALSE_POSITIVE)
                        .withSuppress(true));

        final Map<UUID, List<ComponentVulnAnalysisCompleteSubject>> result =
                withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                        .getForProjectVulnAnalysisComplete(Set.of(project.getUuid())));

        assertThat(result).containsKey(project.getUuid());
        final List<ComponentVulnAnalysisCompleteSubject> findings = result.get(project.getUuid());
        assertThat(findings).hasSize(1);
        assertThat(findings.getFirst().getVulnerabilitiesList()).hasSize(1);
        assertThat(findings.getFirst().getVulnerabilities(0).getVulnId()).isEqualTo("CVE-100");
    }

    @Test
    public void testGetForProjectVulnAnalysisCompleteMultipleProjects() {
        final var projectA = new Project();
        projectA.setName("projectA");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("projectB");
        qm.persist(projectB);

        final var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setName("componentA");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setName("componentB");
        qm.persist(componentB);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-100");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.HIGH);
        qm.persist(vuln);

        qm.addVulnerability(vuln, componentA, "internal");
        qm.addVulnerability(vuln, componentB, "internal");

        final Map<UUID, List<ComponentVulnAnalysisCompleteSubject>> result =
                withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                        .getForProjectVulnAnalysisComplete(Set.of(projectA.getUuid(), projectB.getUuid())));

        assertThat(result).hasSize(2);
        assertThat(result).containsKey(projectA.getUuid());
        assertThat(result).containsKey(projectB.getUuid());
        assertThat(result.get(projectA.getUuid())).hasSize(1);
        assertThat(result.get(projectA.getUuid()).getFirst().getComponent().getName()).isEqualTo("componentA");
        assertThat(result.get(projectB.getUuid())).hasSize(1);
        assertThat(result.get(projectB.getUuid()).getFirst().getComponent().getName()).isEqualTo("componentB");
    }

    @Test
    public void testGetForProjectVulnAnalysisCompleteEmptyInput() {
        final Map<UUID, List<ComponentVulnAnalysisCompleteSubject>> result =
                withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                        .getForProjectVulnAnalysisComplete(Set.of()));

        assertThat(result).isEmpty();
    }

    @Test
    public void testGetForProjectVulnAnalysisCompleteWithAnalysisOverrides() {
        final var project = new Project();
        project.setName("projectName");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("componentName");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-100");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setSeverity(Severity.MEDIUM);
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(5.0));
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, "internal");

        final var analysis = new Analysis();
        analysis.setComponent(component);
        analysis.setVulnerability(vuln);
        analysis.setAnalysisState(AnalysisState.EXPLOITABLE);
        analysis.setSeverity(Severity.CRITICAL);
        analysis.setCvssV3Score(BigDecimal.valueOf(9.8));
        analysis.setCvssV3Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        qm.persist(analysis);

        final Map<UUID, List<ComponentVulnAnalysisCompleteSubject>> result =
                withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                        .getForProjectVulnAnalysisComplete(Set.of(project.getUuid())));

        assertThat(result).containsKey(project.getUuid());
        final var findings = result.get(project.getUuid());
        assertThat(findings).hasSize(1);
        final var vulnerability = findings.getFirst().getVulnerabilities(0);
        assertThat(vulnerability.getSeverity()).isEqualTo("CRITICAL");
        assertThat(vulnerability.getCvssV3()).isEqualTo(9.8);
        assertThat(vulnerability.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    }
}