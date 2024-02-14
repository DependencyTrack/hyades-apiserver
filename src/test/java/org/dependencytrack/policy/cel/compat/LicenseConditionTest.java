package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class LicenseConditionTest extends PersistenceCapableTest {

    @Test
    public void hasMatch() {
        License license = new License();
        license.setName("Apache 2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);

        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE, PolicyCondition.Operator.IS, license.getUuid().toString());
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setName("acme-app");
        component.setResolvedLicense(license);
        component.setProject(project);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

    @Test
    public void noMatch() {
        License license = new License();
        license.setName("Apache 2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);

        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE, PolicyCondition.Operator.IS, UUID.randomUUID().toString());
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setName("acme-app");
        component.setResolvedLicense(license);
        component.setProject(project);

        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void wrongOperator() {
        License license = new License();
        license.setName("Apache 2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);

        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE, PolicyCondition.Operator.MATCHES, license.getUuid().toString());
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setName("acme-app");
        component.setProject(project);
        component.setResolvedLicense(license);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

    @Test
    public void valueIsUnresolved() {
        License license = new License();
        license.setName("Apache 2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);

        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE, PolicyCondition.Operator.IS, "unresolved");

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        Component componentWithoutLicense = new Component();
        componentWithoutLicense.setName("second-component");
        componentWithoutLicense.setProject(project);
        qm.persist(componentWithoutLicense);

        CelPolicyEngine policyEngine = new CelPolicyEngine();

        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentWithoutLicense)).hasSize(1);

        final var componentWithLicense = new Component();
        componentWithLicense.setName("acme-app");
        componentWithLicense.setProject(project);
        componentWithLicense.setResolvedLicense(license);
        qm.persist(componentWithLicense);

        policyEngine.evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(componentWithLicense)).hasSize(0);
    }
}

