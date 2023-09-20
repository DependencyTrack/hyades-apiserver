package org.dependencytrack.policy.cel;

import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.model.AnalyzerIdentity;
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
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
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