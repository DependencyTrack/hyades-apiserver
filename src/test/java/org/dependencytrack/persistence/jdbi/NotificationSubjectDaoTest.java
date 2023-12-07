package org.dependencytrack.persistence.jdbi;

import com.google.protobuf.util.JsonFormat;
import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.persistence.CweImporter;
import org.dependencytrack.proto.notification.v1.NewVulnerabilitySubject;
import org.dependencytrack.proto.notification.v1.NewVulnerableDependencySubject;
import org.junit.Before;
import org.junit.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class NotificationSubjectDaoTest extends AbstractPostgresEnabledTest {

    @Before
    public void setUp() throws Exception {
        super.setUp();

        new CweImporter().processCweDefinitions();
    }

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
        vulnA.setSeverity(Severity.MEDIUM);
        vulnA.setCvssV2BaseScore(BigDecimal.valueOf(1.1));
        vulnA.setCvssV3BaseScore(BigDecimal.valueOf(2.2));
        vulnA.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.3));
        vulnA.setOwaspRRLikelihoodScore(BigDecimal.valueOf(4.4));
        vulnA.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(5.5));
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
        qm.makeAnalysis(component, vulnB, AnalysisState.FALSE_POSITIVE, null, null, null, true);

        final List<NewVulnerabilitySubject> subjects = JdbiFactory.jdbi(qm).withExtension(NotificationSubjectDao.class,
                dao -> dao.getForNewVulnerabilities(component.getUuid(), List.of(vulnA.getUuid(), vulnB.getUuid()),
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
                                    "severity": "MEDIUM",
                                    "source": "NVD",
                                    "subtitle": "vulnASubTitle",
                                    "title": "vulnATitle",
                                    "uuid": "${json-unit.matches:vulnUuid}",
                                    "vulnId": "CVE-100"
                                  },
                                  "vulnerabilityAnalysisLevel": "BOM_UPLOAD_ANALYSIS"
                                }
                                """));
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
        vulnA.setSeverity(Severity.MEDIUM);
        vulnA.setCvssV2BaseScore(BigDecimal.valueOf(1.1));
        vulnA.setCvssV3BaseScore(BigDecimal.valueOf(2.2));
        vulnA.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.3));
        vulnA.setOwaspRRLikelihoodScore(BigDecimal.valueOf(4.4));
        vulnA.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(5.5));
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
        qm.makeAnalysis(component, vulnB, AnalysisState.FALSE_POSITIVE, null, null, null, true);

        final Optional<NewVulnerableDependencySubject> optionalSubject = JdbiFactory.jdbi(qm).withExtension(NotificationSubjectDao.class,
                dao -> dao.getForNewVulnerableDependency(component.getUuid()));

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
                              "severity": "MEDIUM",
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
                              "aliases": [
                                {"vulnId": "GHSA-100", "source": "GITHUB"}
                              ]
                            }
                          ]
                        }
                        """);
    }

}