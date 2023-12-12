package org.dependencytrack.policy.cel;

import alpine.model.IConfigProperty;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.dependencytrack.tasks.BomUploadProcessingTask;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.apache.commons.io.IOUtils.resourceToURL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

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

    /**
     * (Regression-)Test for ensuring that all data available in the policy expression context
     * can be accessed in the expression at runtime.
     * <p>
     * Data being available means:
     * <ul>
     *   <li>Expression requirements were analyzed correctly</li>
     *   <li>Database was retrieved from the database correctly</li>
     *   <li>The mapping from DB data to CEL Protobuf models worked as expected</li>
     * </ul>
     */
    @Test
    public void testEvaluateProjectWithAllFields() {
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
        component.setLicenseExpression("componentLicenseExpression");
        component.setResolvedLicense(license);
        qm.persist(component);

        final var metaComponent = new IntegrityMetaComponent();
        metaComponent.setPurl("componentPurl");
        metaComponent.setPublishedAt(new java.util.Date(222));
        metaComponent.setStatus(FetchStatus.PROCESSED);
        metaComponent.setLastFetch(new Date());
        qm.persist(metaComponent);

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
                  && component.license_expression == "componentLicenseExpression"
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
                  && component.published_at == timestamp("1970-01-01T00:00:00.222Z")
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
    public void testEvaluateProjectWithPolicyOperatorAnyAndAllConditionsMatching() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.name == "acme-app"
                """, PolicyViolation.Type.OPERATIONAL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "acme-lib"
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(2);
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorForComponentAgeLessThan() throws MalformedPackageURLException {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.compare_age("NUMERIC_LESS_THAN", "P666D")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(new PackageURL("pkg:maven/org.http4s/blaze-core_2.12"));
        qm.persist(component);
        Date publishedDate = Date.from(Instant.now());
        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setPublishedAt(publishedDate);
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(new Date());
        qm.createIntegrityMetaComponent(integrityMetaComponent);
        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getValue()).isEqualTo("""
                component.compare_age("NUMERIC_LESS_THAN", "P666D")
                """);
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorForVersionDistance() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.version_distance("NUMERIC_GREATER_THAN_OR_EQUAL", "{ \\"major\\": \\"0\\", \\"minor\\": \\"1\\", \\"patch\\": \\"?\\" }")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("name");
        project.setActive(true);

        final var metaComponent = new RepositoryMetaComponent();
        metaComponent.setRepositoryType(RepositoryType.MAVEN);
        metaComponent.setNamespace("foo");
        metaComponent.setName("bar");
        metaComponent.setLatestVersion("1.3.1");
        metaComponent.setLastCheck(new Date());
        qm.persist(metaComponent);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("foo");
        component.setName("bar");
        component.setPurl("pkg:maven/foo/bar@1.0.0");
        component.setVersion("1.2.3");
        qm.persist(component);

        project.setDirectDependencies("[{\"uuid\":\"" + component.getUuid() + "\"}]");
        qm.persist(project);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getValue()).isEqualTo("""
                component.version_distance("NUMERIC_GREATER_THAN_OR_EQUAL", "{ \\"major\\": \\"0\\", \\"minor\\": \\"1\\", \\"patch\\": \\"?\\" }")
                """);
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorForComponentAgeGreaterThan() throws MalformedPackageURLException {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.compare_age("<", "P666D")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(new PackageURL("pkg:maven/org.http4s/blaze-core_2.12"));
        qm.persist(component);
        Date publishedDate = Date.from(Instant.now());
        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setPublishedAt(publishedDate);
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(new Date());
        qm.createIntegrityMetaComponent(integrityMetaComponent);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getValue()).isEqualTo("""
                component.compare_age("<", "P666D")
                """);
    }

    @Test
    public void testEvaluateProjectWithPublishedAtComparisonGreaterThan() throws Exception {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                (now - component.published_at) > duration("365d")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(new PackageURL("pkg:maven/org.http4s/blaze-core_2.12"));
        qm.persist(component);

        final var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setPublishedAt(Date.from(Instant.EPOCH));
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(new Date());
        qm.persist(integrityMetaComponent);

        final var policyEngine = new CelPolicyEngine();
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWithPublishedAtComparisonLessThan() throws Exception {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                (now - component.published_at) < duration("365d")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(new PackageURL("pkg:maven/org.http4s/blaze-core_2.12"));
        qm.persist(component);

        final var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setPublishedAt(Date.from(Instant.EPOCH));
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(new Date());
        qm.persist(integrityMetaComponent);

        final var policyEngine = new CelPolicyEngine();
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithPublishedAtComparisonUnknown() throws Exception {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                (now - component.published_at) > duration("365d")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(new PackageURL("pkg:maven/org.http4s/blaze-core_2.12"));
        qm.persist(component);

        final var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        // Omitted; Publish date is unknown.
        // integrityMetaComponent.setPublishedAt(Date.from(Instant.EPOCH));
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(new Date());
        qm.persist(integrityMetaComponent);

        final var policyEngine = new CelPolicyEngine();
        policyEngine.evaluateProject(project.getUuid());

        // This matches because the default value of Timestamp is 1970-01-01T00:00:00Z.
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWithPublishedAtComparisonUnknownAndHasCheck() throws Exception {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                has(component.published_at) && (now - component.published_at) > duration("365d")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(new PackageURL("pkg:maven/org.http4s/blaze-core_2.12"));
        qm.persist(component);

        final var integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        // Omitted; Publish date is unknown.
        // integrityMetaComponent.setPublishedAt(Date.from(Instant.EPOCH));
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setLastFetch(new Date());
        qm.persist(integrityMetaComponent);

        final var policyEngine = new CelPolicyEngine();
        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorAnyAndNotAllConditionsMatching() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.name == "acme-app"
                """, PolicyViolation.Type.OPERATIONAL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "someOtherComponentThatIsNotAcmeLib"
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorAnyAndNoConditionsMatching() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.name == "someOtherProjectThatIsNotAcmeApp"
                """, PolicyViolation.Type.OPERATIONAL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "someOtherComponentThatIsNotAcmeLib"
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorAllAndAllConditionsMatching() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.name == "acme-app"
                """, PolicyViolation.Type.OPERATIONAL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "acme-lib"
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(2);
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorAllAndNotAllConditionsMatching() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.name == "acme-app"
                """, PolicyViolation.Type.OPERATIONAL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "someOtherComponentThatIsNotAcmeLib"
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithPolicyOperatorAllAndNoConditionsMatching() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.name == "someOtherProjectThatIsNotAcmeApp"
                """, PolicyViolation.Type.OPERATIONAL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "someOtherComponentThatIsNotAcmeLib"
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithPolicyAssignedToProject() {
        final var policyA = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policyA, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name.startsWith("acme-lib")
                """, PolicyViolation.Type.OPERATIONAL);
        final var policyB = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policyB, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name.startsWith("acme-lib")
                """, PolicyViolation.Type.OPERATIONAL);

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);
        final var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setName("acme-lib");
        qm.persist(componentA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);
        final var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setName("acme-lib");
        qm.persist(componentB);

        policyB.setProjects(List.of(projectB));
        qm.persist(policyB);

        new CelPolicyEngine().evaluateProject(projectA.getUuid());
        new CelPolicyEngine().evaluateProject(projectB.getUuid());

        assertThat(qm.getAllPolicyViolations(projectA)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(projectB)).hasSize(2);
    }

    @Test
    public void testEvaluateProjectWithPolicyAssignedToProjectParent() {
        final var policyA = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policyA, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name.startsWith("acme-lib")
                """, PolicyViolation.Type.OPERATIONAL);
        final var policyB = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policyB, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name.startsWith("acme-lib")
                """, PolicyViolation.Type.OPERATIONAL);

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);
        final var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setName("acme-lib");
        qm.persist(componentA);

        final var projectParentB = new Project();
        projectParentB.setName("acme-app-parent-b");
        qm.persist(projectParentB);

        policyB.setProjects(List.of(projectParentB));
        policyB.setIncludeChildren(true);
        qm.persist(policyB);

        final var projectB = new Project();
        projectB.setParent(projectParentB);
        projectB.setName("acme-app-b");
        qm.persist(projectB);
        final var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setName("acme-lib");
        qm.persist(componentB);

        new CelPolicyEngine().evaluateProject(projectA.getUuid());
        new CelPolicyEngine().evaluateProject(projectB.getUuid());

        assertThat(qm.getAllPolicyViolations(projectA)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(projectB)).hasSize(2);
    }

    @Test
    public void testEvaluateProjectWithPolicyAssignedToTag() {
        final Tag tag = qm.createTag("foo");

        final var policyA = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policyA, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name.startsWith("acme-lib")
                """, PolicyViolation.Type.OPERATIONAL);
        final var policyB = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policyB, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name.startsWith("acme-lib")
                """, PolicyViolation.Type.OPERATIONAL);
        policyB.setTags(List.of(tag));
        qm.persist(policyB);

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);
        final var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setName("acme-lib");
        qm.persist(componentA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);
        final var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setName("acme-lib");
        qm.persist(componentB);

        qm.bind(projectB, List.of(tag));

        new CelPolicyEngine().evaluateProject(projectA.getUuid());
        new CelPolicyEngine().evaluateProject(projectB.getUuid());

        assertThat(qm.getAllPolicyViolations(projectA)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(projectB)).hasSize(2);
    }

    @Test
    public void testEvaluateProjectWithInvalidScript() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.doesNotExist == "foo"
                """, PolicyViolation.Type.OPERATIONAL);
        final PolicyCondition validCondition = qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION,
                PolicyCondition.Operator.MATCHES, """
                        project.name == "acme-app"
                        """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        assertThatNoException().isThrownBy(() -> new CelPolicyEngine().evaluateProject(project.getUuid()));
        assertThat(qm.getAllPolicyViolations(component)).satisfiesExactly(violation ->
                assertThat(violation.getPolicyCondition()).isEqualTo(validCondition)
        );
    }

    @Test
    public void testEvaluateProjectWithScriptExecutionException() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.last_bom_import == timestamp("invalid")
                """, PolicyViolation.Type.OPERATIONAL);
        final PolicyCondition validCondition = qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION,
                PolicyCondition.Operator.MATCHES, """
                        project.name == "acme-app"
                        """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        assertThatNoException().isThrownBy(() -> new CelPolicyEngine().evaluateProject(project.getUuid()));
        assertThat(qm.getAllPolicyViolations(component)).satisfiesExactly(violation ->
                assertThat(violation.getPolicyCondition()).isEqualTo(validCondition)
        );
    }

    @Test
    public void testEvaluateProjectWithFuncProjectDependsOnComponent() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.depends_on(org.dependencytrack.policy.v1.Component{name: "acme-lib-a"})
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
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

//    @Test
//    public void testEvaluateProjectWithFuncComponentIsDependencyOfComponent() {
//        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
//        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
//                component.is_dependency_of(org.dependencytrack.policy.v1.Component{name: "acme-lib-a"})
//                """, PolicyViolation.Type.OPERATIONAL);
//
//        final var project = new Project();
//        project.setName("acme-app");
//        qm.persist(project);
//
//        final var componentA = new Component();
//        componentA.setProject(project);
//        componentA.setName("acme-lib-a");
//        qm.persist(componentA);
//
//        final var componentB = new Component();
//        componentB.setProject(project);
//        componentB.setName("acme-lib-b");
//        qm.persist(componentB);
//
//        project.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentA).toJSON()));
//        qm.persist(project);
//        componentA.setDirectDependencies("[%s]".formatted(new ComponentIdentity(componentB).toJSON()));
//        qm.persist(componentA);
//
//        new CelPolicyEngine().evaluateProject(project.getUuid());
//
//        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
//        assertThat(qm.getAllPolicyViolations(componentB)).hasSize(1);
//    }

    @Test
    public void testEvaluateProjectWithFuncMatchesRange() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.matches_range("vers:generic/<1")
                    && component.matches_range("vers:golang/>0|<v2.0.0")
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("0.1");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        componentA.setVersion("v1.9.3");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        componentB.setVersion("v2.0.0");
        qm.persist(componentB);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentA)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWithFuncMatchesRangeWithInvalidRange() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                project.matches_range("foo")
                    && component.matches_range("bar")
                """);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("0.1");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        componentA.setVersion("v1.9.3");
        qm.persist(componentA);

        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        componentB.setVersion("v2.0.0");
        qm.persist(componentB);

        assertThatNoException().isThrownBy(() -> new CelPolicyEngine().evaluateProject(project.getUuid()));
        assertThat(qm.getAllPolicyViolations(componentA)).isEmpty();
        assertThat(qm.getAllPolicyViolations(componentB)).isEmpty();
    }

    @Test
    public void testEvaluateProjectWhenProjectDoesNotExist() {
        assertThatNoException().isThrownBy(() -> new CelPolicyEngine().evaluateProject(UUID.randomUUID()));
    }

    @Test
    public void testEvaluateComponent() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                component.name == "acme-lib"
                """, PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        new CelPolicyEngine().evaluateComponent(component.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void testEvaluateComponentWhenComponentDoesNotExist() {
        assertThatNoException().isThrownBy(() -> new CelPolicyEngine().evaluateComponent(UUID.randomUUID()));
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
        // NOTE: This behavior changed in CelPolicyEngine over the legacy PolicyEngine.
        // A matched PolicyCondition can now only yield a single PolicyViolation, whereas
        // with the legacy PolicyEngine, multiple PolicyViolations could be raised.
//        Assert.assertEquals(3, violations.size());
//        PolicyViolation policyViolation = violations.get(0);
//        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
//        Assert.assertEquals(PolicyCondition.Subject.SEVERITY, policyViolation.getPolicyCondition().getSubject());
//        policyViolation = violations.get(1);
//        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
//        Assert.assertEquals(PolicyCondition.Subject.SEVERITY, policyViolation.getPolicyCondition().getSubject());
//        policyViolation = violations.get(2);
//        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
//        Assert.assertEquals(PolicyCondition.Subject.PACKAGE_URL, policyViolation.getPolicyCondition().getSubject());
        assertThat(violations).satisfiesExactlyInAnyOrder(
                violation -> {
                    assertThat(violation.getComponent().getName()).isEqualTo("Log4J");
                    assertThat(violation.getPolicyCondition().getSubject()).isEqualTo(PolicyCondition.Subject.SEVERITY);
                },
                violation -> {
                    assertThat(violation.getComponent().getName()).isEqualTo("Log4J");
                    assertThat(violation.getPolicyCondition().getSubject()).isEqualTo(PolicyCondition.Subject.PACKAGE_URL);
                }
        );
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
    @Ignore  // Un-ignore for manual profiling purposes.
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