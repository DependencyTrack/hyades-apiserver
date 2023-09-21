package org.dependencytrack.policy.cel;

import alpine.model.IConfigProperty;
import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.sql.Date;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.apache.commons.io.IOUtils.resourceToURL;
import static org.assertj.core.api.Assertions.assertThat;

public class CelPolicyEngineTest extends AbstractPostgresEnabledTest {

    @Before
    public void setUp() throws Exception {
        super.setUp();

        // Enable processing of CycloneDX BOMs
        qm.createConfigProperty(ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getGroupName(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getPropertyName(), "true",
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getPropertyType(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getDescription());
    }

    @Test
    public void test() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final PolicyCondition policyConditionA = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                        "critical" in project.tags
                            && component.name == "bar"
                            && vulns.exists(v, v.source == "SNYK")
                            && component.resolved_license.groups.exists(lg, lg.name == "Permissive")
                        """);
        policyConditionA.setViolationType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyConditionA);

        final var policy2 = qm.createPolicy("policy2", Policy.Operator.ALL, Policy.ViolationState.WARN);
        qm.createPolicyCondition(policy2, PolicyCondition.Subject.VULNERABILITY_ID, PolicyCondition.Operator.IS, "CVE-123");

        final var policy3 = qm.createPolicy("policy3", Policy.Operator.ALL, Policy.ViolationState.INFO);
        final PolicyCondition condition3 = qm.createPolicyCondition(policy3, PolicyCondition.Subject.SWID_TAGID, PolicyCondition.Operator.MATCHES, "foo");

        final var policy4 = qm.createPolicy("policy4", Policy.Operator.ALL, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy4, PolicyCondition.Subject.CWE, PolicyCondition.Operator.CONTAINS_ALL, "CWE-666, CWE-123, 555");

        final var project = new Project();
        project.setName("foo");
        qm.persist(project);
        qm.bind(project, List.of(
                qm.createTag("public-facing"),
                qm.createTag("critical")
        ));

        final var license = new License();
        license.setName("MIT");
        license.setLicenseId("MIT");
        qm.persist(license);

        final var licenseGroup = new LicenseGroup();
        licenseGroup.setName("Permissive");
        licenseGroup.setLicenses(List.of(license));
        qm.persist(licenseGroup);

        final var component = new Component();
        component.setProject(project);
        component.setName("bar");
        component.setResolvedLicense(license);
        qm.persist(component);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("CVE-123");
        vulnA.setSource(Vulnerability.Source.NVD);
        vulnA.setCreated(Date.from(LocalDateTime.now().minusYears(1).toInstant(ZoneOffset.UTC)));
        qm.persist(vulnA);

        final var vulnB = new Vulnerability();
        vulnB.setVulnId("SNYK-123");
        vulnB.setSource(Vulnerability.Source.SNYK);
        vulnB.setCwes(List.of(555, 666, 123));
        qm.persist(vulnB);

        qm.addVulnerability(vulnA, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        qm.addVulnerability(vulnB, component, AnalyzerIdentity.SNYK_ANALYZER);

        final var existingViolation = new PolicyViolation();
        existingViolation.setComponent(component);
        existingViolation.setPolicyCondition(condition3);
        existingViolation.setType(PolicyViolation.Type.OPERATIONAL);
        existingViolation.setTimestamp(new java.util.Date());
        qm.persist(existingViolation);

        final var policyEngine = new CelPolicyEngine();
        policyEngine.evaluateProject(project.getUuid());

        final List<PolicyViolation> violations = qm.getAllPolicyViolations(component);
        assertThat(violations).isNotEmpty();
    }

    @Test
    public void testWithAllFields() {
        final var project = new Project();
        project.setUuid(UUID.fromString("d7173786-60aa-4a4f-a950-c92fe6422307"));
        project.setGroup("projectGroup");
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setClassifier(Classifier.APPLICATION);
        project.setActive(true);
        project.setCpe("projectCpe");
        project.setPurl("projectPurl");
        project.setSwidTagId("projectSwidTagId");
        project.setLastBomImport(new java.util.Date());
        qm.persist(project);

        qm.createProjectProperty(project, "propertyGroup", "propertyName", "propertyValue", IConfigProperty.PropertyType.STRING, null);

        qm.bind(project, List.of(
                qm.createTag("projectTagA"),
                qm.createTag("projectTagB")
        ));

        final var licenseGroup = new LicenseGroup();
        licenseGroup.setUuid(UUID.fromString("bbdb62f8-d854-4e43-a9ed-36481545c201"));
        licenseGroup.setName("licenseGroupName");
        qm.persist(licenseGroup);

        final var license = new License();
        license.setUuid(UUID.fromString("dc9876c2-0adc-422b-9f71-3ca78285f138"));
        license.setLicenseId("resolvedLicenseId");
        license.setName("resolvedLicenseName");
        license.setOsiApproved(true);
        license.setFsfLibre(true);
        license.setDeprecatedLicenseId(true);
        license.setCustomLicense(true);
        license.setLicenseGroups(List.of(licenseGroup));
        qm.persist(license);

        final var component = new Component();
        component.setProject(project);
        component.setUuid(UUID.fromString("7e5f6465-d2f2-424f-b1a4-68d186fa2b46"));
        component.setGroup("componentGroup");
        component.setName("componentName");
        component.setVersion("componentVersion");
        component.setClassifier(Classifier.LIBRARY);
        component.setCpe("componentCpe");
        component.setPurl("componentPurl");
        component.setSwidTagId("componentSwidTagId");
        component.setInternal(true);
        component.setMd5("componentMd5");
        component.setSha1("componentSha1");
        component.setSha256("componentSha256");
        component.setSha384("componentSha384");
        component.setSha512("componentSha512");
        component.setSha3_256("componentSha3_256");
        component.setSha3_384("componentSha3_384");
        component.setSha3_512("componentSha3_512");
        component.setBlake2b_256("componentBlake2b_256");
        component.setBlake2b_384("componentBlake2b_384");
        component.setBlake2b_512("componentBlake2b_512");
        component.setBlake3("componentBlake3");
        component.setLicense("componentLicenseName");
        component.setResolvedLicense(license);
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setUuid(UUID.fromString("ffe9743f-b916-431e-8a68-9b3ac56db72c"));
        vuln.setVulnId("CVE-001");
        vuln.setSource(Vulnerability.Source.NVD);
        vuln.setCwes(List.of(666, 777));
        vuln.setCreated(new java.util.Date(666));
        vuln.setPublished(new java.util.Date(777));
        vuln.setUpdated(new java.util.Date(888));
        vuln.setSeverity(Severity.INFO);
        vuln.setCvssV2BaseScore(BigDecimal.valueOf(6.0));
        vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(6.4));
        vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(6.8));
        vuln.setCvssV2Vector("(AV:N/AC:M/Au:S/C:P/I:P/A:P)");
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(9.1));
        vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(5.3));
        vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(3.1));
        vuln.setCvssV3Vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L");
        vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(4.5));
        vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(5.0));
        vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.75));
        vuln.setOwaspRRVector("(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)");
        vuln.setEpssScore(BigDecimal.valueOf(0.6));
        vuln.setEpssPercentile(BigDecimal.valueOf(0.2));
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, AnalyzerIdentity.INTERNAL_ANALYZER);

        final var vulnAlias = new VulnerabilityAlias();
        vulnAlias.setCveId("CVE-001");
        vulnAlias.setGhsaId("GHSA-001");
        vulnAlias.setGsdId("GSD-001");
        vulnAlias.setInternalId("INT-001");
        vulnAlias.setOsvId("OSV-001");
        vulnAlias.setSnykId("SNYK-001");
        vulnAlias.setSonatypeId("SONATYPE-001");
        vulnAlias.setVulnDbId("VULNDB-001");
        qm.synchronizeVulnerabilityAlias(vulnAlias);

        final Policy policy = qm.createPolicy("policy", Policy.Operator.ALL, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.uuid == "__COMPONENT_UUID__"
                  && component.group == "componentGroup"
                  && component.name == "componentName"
                  && component.version == "componentVersion"
                  && component.classifier == "LIBRARY"
                  && component.cpe == "componentCpe"
                  && component.purl == "componentPurl"
                  && component.swid_tag_id == "componentSwidTagId"
                  && component.is_internal
                  && component.md5 == "componentmd5"
                  && component.sha1 == "componentsha1"
                  && component.sha256 == "componentsha256"
                  && component.sha384 == "componentsha384"
                  && component.sha512 == "componentsha512"
                  && component.sha3_256 == "componentsha3_256"
                  && component.sha3_384 == "componentsha3_384"
                  && component.sha3_512 == "componentsha3_512"
                  && component.blake2b_256 == "componentBlake2b_256"
                  && component.blake2b_384 == "componentBlake2b_384"
                  && component.blake2b_512 == "componentBlake2b_512"
                  && component.blake3 == "componentBlake3"
                  && component.license_name == "componentLicenseName"
                  && !has(component.license_expression)
                  && component.resolved_license.uuid == "__RESOLVED_LICENSE_UUID__"
                  && component.resolved_license.id == "resolvedLicenseId"
                  && component.resolved_license.name == "resolvedLicenseName"
                  && component.resolved_license.is_osi_approved
                  && component.resolved_license.is_fsf_libre
                  && component.resolved_license.is_deprecated_id
                  && component.resolved_license.is_custom
                  && component.resolved_license.groups.all(licenseGroup,
                       licenseGroup.uuid == "__LICENSE_GROUP_UUID__"
                         && licenseGroup.name == "licenseGroupName"
                     )
                  && project.uuid == "__PROJECT_UUID__"
                  && project.group == "projectGroup"
                  && project.name == "projectName"
                  && project.version == "projectVersion"
                  && project.classifier == "APPLICATION"
                  && project.is_active
                  && project.cpe == "projectCpe"
                  && project.purl == "projectPurl"
                  && project.swid_tag_id == "projectSwidTagId"
                  && has(project.last_bom_import)
                  && "projecttaga" in project.tags
                  && project.properties.all(property,
                       property.group == "propertyGroup"
                         && property.name == "propertyName"
                         && property.value == "propertyValue"
                         && property.type == "STRING"
                     )
                  && vulns.all(vuln,
                       vuln.uuid == "__VULN_UUID__"
                         && vuln.id == "CVE-001"
                         && vuln.source == "NVD"
                         && 666 in vuln.cwes
                         && vuln.aliases
                              .map(alias, alias.source + ":" + alias.id)
                              .all(alias, alias in [
                                "NVD:CVE-001",
                                "GITHUB:GHSA-001",
                                "GSD:GSD-001",
                                "INTERNAL:INT-001",
                                "OSV:OSV-001",
                                "SNYK:SNYK-001",
                                "OSSINDEX:SONATYPE-001",
                                "VULNDB:VULNDB-001"
                              ])
                         && vuln.created == timestamp("1970-01-01T00:00:00.666Z")
                         && vuln.published == timestamp("1970-01-01T00:00:00.777Z")
                         && vuln.updated == timestamp("1970-01-01T00:00:00.888Z")
                         && vuln.severity == "INFO"
                         && vuln.cvssv2_base_score == 6.0
                         && vuln.cvssv2_impact_subscore == 6.4
                         && vuln.cvssv2_exploitability_subscore == 6.8
                         && vuln.cvssv2_vector == "(AV:N/AC:M/Au:S/C:P/I:P/A:P)"
                         && vuln.cvssv3_base_score == 9.1
                         && vuln.cvssv3_impact_subscore == 5.3
                         && vuln.cvssv3_exploitability_subscore == 3.1
                         && vuln.cvssv3_vector == "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L"
                         && vuln.owasp_rr_likelihood_score == 4.5
                         && vuln.owasp_rr_technical_impact_score == 5.0
                         && vuln.owasp_rr_business_impact_score == 3.75
                         && vuln.owasp_rr_vector == "(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)"
                         && vuln.epss_score == 0.6
                         && vuln.epss_percentile == 0.2
                     )
                """
                .replace("__COMPONENT_UUID__", component.getUuid().toString())
                .replace("__PROJECT_UUID__", project.getUuid().toString())
                .replace("__RESOLVED_LICENSE_UUID__", license.getUuid().toString())
                .replace("__LICENSE_GROUP_UUID__", licenseGroup.getUuid().toString())
                .replace("__VULN_UUID__", vuln.getUuid().toString()), PolicyViolation.Type.OPERATIONAL);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(project)).hasSize(1);
    }

    @Test
    public void testIsDirectDependency() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final PolicyCondition policyCondition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                        component.is_direct_dependency
                        """);
        policyCondition.setViolationType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyCondition);

        final var project = new Project();
        project.setName("foo");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("bar");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("baz");
        qm.persist(componentB);

        project.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentA).toJSON()));
        qm.persist(project);
        componentA.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentB).toJSON()));
        qm.persist(componentA);

        final var policyEngine = new CelPolicyEngine();

        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
    }

    @Test
    public void testProjectDependsOnComponent() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final PolicyCondition policyCondition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                        project.depends_on(org.hyades.policy.v1.Component{name: "foo"})
                        """);
        policyCondition.setViolationType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyCondition);

        final var project = new Project();
        project.setName("foo");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("bar");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("baz");
        qm.persist(componentB);

        project.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentA).toJSON()));
        qm.persist(project);
        componentA.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentB).toJSON()));
        qm.persist(componentA);

        final var policyEngine = new CelPolicyEngine();

        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentB)).hasSize(1);
    }

    @Test
    public void testMatchesRange() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final PolicyCondition policyCondition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                        project.matches_range("vers:generic/<1")
                            && component.matches_range("vers:golang/>0|<v2.0.0")
                        """);
        policyCondition.setViolationType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyCondition);

        final var project = new Project();
        project.setName("foo");
        project.setVersion("0.1");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("bar");
        componentA.setVersion("v1.9.3");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("baz");
        componentB.setVersion("v2.0.0");
        qm.persist(componentB);

        project.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentA).toJSON()));
        qm.persist(project);
        componentA.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentB).toJSON()));
        qm.persist(componentA);

        final var policyEngine = new CelPolicyEngine();

        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
    }

    @Test
    public void issue1924() {
        Policy policy = qm.createPolicy("Policy 1924", Policy.Operator.ALL, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.SEVERITY, PolicyCondition.Operator.IS, Severity.CRITICAL.name());
        qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.NO_MATCH, "pkg:deb");
        Project project = qm.createProject("My Project", null, "1", null, null, null, true, false);
        qm.persist(project);
        ArrayList<Component> components = new ArrayList<>();
        Component component = new Component();
        component.setName("OpenSSL");
        component.setVersion("3.0.2-0ubuntu1.6");
        component.setPurl("pkg:deb/openssl@3.0.2-0ubuntu1.6");
        component.setProject(project);
        components.add(component);
        qm.persist(component);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("1");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        vulnerability = new Vulnerability();
        vulnerability.setVulnId("2");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        component = new Component();
        component.setName("Log4J");
        component.setVersion("1.2.16");
        component.setPurl("pkg:mvn/log4j/log4j@1.2.16");
        component.setProject(project);
        components.add(component);
        qm.persist(component);
        vulnerability = new Vulnerability();
        vulnerability.setVulnId("3");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        vulnerability = new Vulnerability();
        vulnerability.setVulnId("4");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        CelPolicyEngine policyEngine = new CelPolicyEngine();
        policyEngine.evaluateProject(project.getUuid());
        final List<PolicyViolation> violations = qm.getAllPolicyViolations();
        Assert.assertEquals(3, violations.size());
        PolicyViolation policyViolation = violations.get(0);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(PolicyCondition.Subject.SEVERITY, policyViolation.getPolicyCondition().getSubject());
        policyViolation = violations.get(1);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(PolicyCondition.Subject.SEVERITY, policyViolation.getPolicyCondition().getSubject());
        policyViolation = violations.get(2);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(PolicyCondition.Subject.PACKAGE_URL, policyViolation.getPolicyCondition().getSubject());
    }

    @Test
    public void issue2455() {
        Policy policy = qm.createPolicy("Policy 1924", Policy.Operator.ALL, Policy.ViolationState.INFO);

        License license = new License();
        license.setName("Apache 2.0");
        license.setLicenseId("Apache-2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        LicenseGroup lg = qm.createLicenseGroup("Test License Group 1");
        lg.setLicenses(Collections.singletonList(license));
        lg = qm.persist(lg);
        lg = qm.detach(LicenseGroup.class, lg.getId());
        license = qm.detach(License.class, license.getId());
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS_NOT, lg.getUuid().toString());

        license = new License();
        license.setName("MIT");
        license.setLicenseId("MIT");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        lg = qm.createLicenseGroup("Test License Group 2");
        lg.setLicenses(Collections.singletonList(license));
        lg = qm.persist(lg);
        lg = qm.detach(LicenseGroup.class, lg.getId());
        license = qm.detach(License.class, license.getId());
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS_NOT, lg.getUuid().toString());

        Project project = qm.createProject("My Project", null, "1", null, null, null, true, false);
        qm.persist(project);

        license = new License();
        license.setName("LGPL");
        license.setLicenseId("LGPL");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        ArrayList<Component> components = new ArrayList<>();
        Component component = new Component();
        component.setName("Log4J");
        component.setVersion("2.0.0");
        component.setProject(project);
        component.setResolvedLicense(license);
        components.add(component);
        qm.persist(component);

        CelPolicyEngine policyEngine = new CelPolicyEngine();
        policyEngine.evaluateProject(project.getUuid());
        final List<PolicyViolation> violations = qm.getAllPolicyViolations();
        Assert.assertEquals(2, violations.size());
        PolicyViolation policyViolation = violations.get(0);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(PolicyCondition.Subject.LICENSE_GROUP, policyViolation.getPolicyCondition().getSubject());
        policyViolation = violations.get(1);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(PolicyCondition.Subject.LICENSE_GROUP, policyViolation.getPolicyCondition().getSubject());
    }

    @Test
    public void testWithBloatedBom() throws Exception {
        // Import all default objects (includes licenses and license groups).
        new DefaultObjectGenerator().contextInitialized(null);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.2.3");
        qm.persist(project);

        // Create a policy that will be violated by the vast majority (>8000) components.
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final PolicyCondition policyConditionA = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                        component.resolved_license.groups.exists(lg, lg.name == "Permissive")
                        """);
        policyConditionA.setViolationType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyConditionA);

        // Import the bloated BOM.
        new BomUploadProcessingTask().inform(new BomUploadEvent(qm.detach(Project.class, project.getId()), createTempBomFile("bom-bloated.json")));

        // Evaluate policies on the project.
        new CelPolicyEngine().evaluateProject(project.getUuid());
    }

    private static File createTempBomFile(final String testFileName) throws Exception {
        // The task will delete the input file after processing it,
        // so create a temporary copy to not impact other tests.
        final Path bomFilePath = Files.createTempFile(null, null);
        Files.copy(Paths.get(resourceToURL("/unit/" + testFileName).toURI()), bomFilePath, StandardCopyOption.REPLACE_EXISTING);
        return bomFilePath.toFile();
    }

}