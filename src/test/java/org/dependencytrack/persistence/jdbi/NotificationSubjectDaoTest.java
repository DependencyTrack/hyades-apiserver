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
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.proto.notification.v1.NewVulnerabilitySubject;
import org.dependencytrack.proto.notification.v1.NewVulnerableDependencySubject;
import org.dependencytrack.proto.notification.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.junit.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
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

        final var vulnAlias = new VulnerabilityAlias();
        vulnAlias.setCveId("CVE-100");
        vulnAlias.setGhsaId("GHSA-100");
        qm.synchronizeVulnerabilityAlias(vulnAlias);

        qm.addVulnerability(vulnA, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        qm.addVulnerability(vulnB, component, AnalyzerIdentity.INTERNAL_ANALYZER);

        // Suppress vulnB, it should not appear in the query results.
        withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                .makeAnalysis(project.getId(), component.getId(), vulnB.getId(), AnalysisState.FALSE_POSITIVE, null, null, null, true));

        final List<NewVulnerabilitySubject> subjects = withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                .getForNewVulnerabilities(component.getUuid(), List.of(vulnA.getUuid(), vulnB.getUuid()),
                        VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));

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
                                  },
                                  "vulnerabilityAnalysisLevel": "BOM_UPLOAD_ANALYSIS",
                                  "affectedProjectsReference": {
                                    "apiUri": "/api/v1/vulnerability/source/NVD/vuln/CVE-100/projects",
                                    "frontendUri": "/vulnerabilities/NVD/CVE-100/affectedProjects"
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

        qm.addVulnerability(vuln, component, AnalyzerIdentity.INTERNAL_ANALYZER);

        final var analysis = new Analysis();
        analysis.setComponent(component);
        analysis.setVulnerability(vuln);
        analysis.setAnalysisState(AnalysisState.EXPLOITABLE);
        analysis.setSeverity(Severity.CRITICAL);
        analysis.setCvssV3Vector("cvssV3VectorOverwrite");
        analysis.setCvssV3Score(BigDecimal.valueOf(10.0));
        qm.persist(analysis);

        final List<NewVulnerabilitySubject> subjects = withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                .getForNewVulnerabilities(component.getUuid(), List.of(vuln.getUuid()),
                        VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));

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
                            "name": "projectName"
                          },
                          "vulnerability": {
                            "uuid": "${json-unit.matches:vulnUuid}",
                            "vulnId": "CVE-100",
                            "source": "NVD",
                            "cvssv3": 10.0,
                            "severity": "CRITICAL",
                            "cvssV3Vector": "cvssV3VectorOverwrite"
                          },
                          "vulnerabilityAnalysisLevel": "BOM_UPLOAD_ANALYSIS",
                          "affectedProjects": [
                            {
                              "uuid": "${json-unit.matches:projectUuid}",
                              "name": "projectName"
                            }
                          ],
                          "affectedProjectsReference": {
                            "apiUri": "/api/v1/vulnerability/source/NVD/vuln/CVE-100/projects",
                            "frontendUri": "/vulnerabilities/NVD/CVE-100/affectedProjects"
                          }
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

        final var vulnAlias = new VulnerabilityAlias();
        vulnAlias.setCveId("CVE-100");
        vulnAlias.setGhsaId("GHSA-100");
        qm.synchronizeVulnerabilityAlias(vulnAlias);

        qm.addVulnerability(vulnA, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        qm.addVulnerability(vulnB, component, AnalyzerIdentity.INTERNAL_ANALYZER);

        // Suppress vulnB, it should not appear in the query results.
        withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                .makeAnalysis(project.getId(), component.getId(), vulnB.getId(), AnalysisState.FALSE_POSITIVE, null, null, null, true));

        final Optional<NewVulnerableDependencySubject> optionalSubject = withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                .getForNewVulnerableDependency(component.getUuid()));

        assertThat(optionalSubject).isPresent();
        assertThatJson(JsonFormat.printer().print(optionalSubject.get()))
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

        qm.addVulnerability(vuln, component, AnalyzerIdentity.INTERNAL_ANALYZER);

        final var analysis = new Analysis();
        analysis.setComponent(component);
        analysis.setVulnerability(vuln);
        analysis.setAnalysisState(AnalysisState.EXPLOITABLE);
        analysis.setSeverity(Severity.CRITICAL);
        analysis.setCvssV3Vector("cvssV3VectorOverwrite");
        analysis.setCvssV3Score(BigDecimal.valueOf(10.0));
        qm.persist(analysis);

        final Optional<NewVulnerableDependencySubject> optionalSubject = withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                .getForNewVulnerableDependency(component.getUuid()));

        assertThat(optionalSubject).isPresent();
        assertThatJson(JsonFormat.printer().print(optionalSubject.get()))
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
                            "name": "projectName"
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

        final var vulnAlias = new VulnerabilityAlias();
        vulnAlias.setCveId("CVE-100");
        vulnAlias.setGhsaId("GHSA-100");
        qm.synchronizeVulnerabilityAlias(vulnAlias);

        qm.addVulnerability(vulnA, component, AnalyzerIdentity.INTERNAL_ANALYZER);

        // Suppress vulnB, it should not appear in the query results.
        withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                .makeAnalysis(project.getId(), component.getId(), vulnA.getId(), AnalysisState.NOT_AFFECTED, null, null, null, false));

        var policyAnalysis = qm.getAnalysis(component, vulnA);

        final Optional<VulnerabilityAnalysisDecisionChangeSubject> optionalSubject = withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                .getForProjectAuditChange(component.getUuid(), vulnA.getUuid(), policyAnalysis.getAnalysisState(), policyAnalysis.isSuppressed()));

        assertThat(optionalSubject.get()).satisfies(subject ->
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
}