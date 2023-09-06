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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.policy;

import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import io.micrometer.core.instrument.Timer;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * A lightweight policy engine that evaluates a list of components against
 * all defined policies. Each policy is evaluated using individual policy
 * evaluators. Additional evaluators can be easily added in the future.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
public class PolicyEngine {

    private static final Logger LOGGER = Logger.getLogger(PolicyEngine.class);

    private final List<PolicyEvaluator> evaluators = new ArrayList<>();

    public PolicyEngine() {
        evaluators.add(new SeverityPolicyEvaluator());
        evaluators.add(new CoordinatesPolicyEvaluator());
        evaluators.add(new LicenseGroupPolicyEvaluator());
        evaluators.add(new LicensePolicyEvaluator());
        evaluators.add(new PackageURLPolicyEvaluator());
        evaluators.add(new CpePolicyEvaluator());
        evaluators.add(new SwidTagIdPolicyEvaluator());
        evaluators.add(new VersionPolicyEvaluator());
        evaluators.add(new ComponentAgePolicyEvaluator());
        evaluators.add(new ComponentHashPolicyEvaluator());
        evaluators.add(new CwePolicyEvaluator());
        evaluators.add(new VulnerabilityIdPolicyEvaluator());
    }

    public List<PolicyViolation> evaluateProject(final UUID projectUuid) {
        final Timer.Sample timerSample = Timer.start();
        final var violations = new ArrayList<PolicyViolation>();
        try (final var qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, projectUuid, List.of(Project.FetchGroup.IDENTIFIERS.name()));
            if (project == null) {
                LOGGER.warn("Unable to evaluate project %s against applicable policies, because it does not exist"
                        .formatted(projectUuid));
                return violations;
            }

            final List<Policy> policies = qm.getApplicablePolicies(project);
            if (policies.isEmpty()) {
                // With no applicable policies, there's no way to resolve violations.
                // As a compensation, simply delete all violations associated with the project.
                qm.deletePolicyViolations(project);
                return Collections.emptyList();
            }

            LOGGER.debug("Fetching first components page for project " + projectUuid);
            List<Component> components = fetchNextComponentsPage(qm.getPersistenceManager(), project, null);
            while (!components.isEmpty()) {
                for (final Component component : components) {
                    violations.addAll(evaluate(qm, policies, component));
                }

                LOGGER.debug("Fetching next components page for project " + projectUuid);
                final long lastId = components.get(components.size() - 1).getId();
                components = fetchNextComponentsPage(qm.getPersistenceManager(), project, lastId);
            }
        } finally {
            timerSample.stop(Timer
                    .builder("policy_evaluation")
                    .tag("target", "project")
                    .register(Metrics.getRegistry()));
        }
        return violations;
    }

    public List<PolicyViolation> evaluate(UUID componentUuid) {
        final Timer.Sample timerSample = Timer.start();
        final List<PolicyViolation> violations = new ArrayList<>();
        try (final QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, componentUuid);
            if (component == null) {
                LOGGER.warn("Unable to evaluate component " + componentUuid + " against applicable policies, because it does not exist");
                return Collections.emptyList();
            }

            final List<Policy> policies = qm.getApplicablePolicies(component.getProject());
            if (policies.isEmpty()) {
                // With no applicable policies, there's no way to resolve violations.
                // As a compensation, simply delete all violations associated with the component.
                qm.deletePolicyViolationsOfComponent(component);
                return Collections.emptyList();
            }

            LOGGER.debug("Evaluating component " + componentUuid + " against applicable policies");
            violations.addAll(this.evaluate(qm, policies, component));
        } finally {
            timerSample.stop(Timer
                    .builder("policy_evaluation")
                    .tag("target", "component")
                    .register(Metrics.getRegistry()));
        }
        return violations;
    }

    private List<PolicyViolation> evaluate(final QueryManager qm, final List<Policy> policies, Component component) {
        final List<PolicyViolation> policyViolations = new ArrayList<>();
        final List<PolicyViolation> existingPolicyViolations = qm.detach(qm.getAllPolicyViolations(component));
        for (final Policy policy : policies) {
            List<Vulnerability> vulnerabilities = new ArrayList<>();
            if (policy.getPolicyConditions().stream().anyMatch(policyCondition -> policyCondition.getSubject() == PolicyCondition.Subject.SEVERITY ||
                    policyCondition.getSubject() == PolicyCondition.Subject.CWE ||
                    policyCondition.getSubject() == PolicyCondition.Subject.VULNERABILITY_ID)) {
                vulnerabilities = qm.getAllVulnerabilities(component, false);
            }
            LOGGER.debug("Evaluating component (" + component.getUuid() + ") against policy (" + policy.getUuid() + ")");
            final List<PolicyConditionViolation> policyConditionViolations = new ArrayList<>();
            int policyConditionsViolated = 0;
            for (final PolicyEvaluator evaluator : evaluators) {
                evaluator.setQueryManager(qm);
                final List<PolicyConditionViolation> policyConditionViolationsFromEvaluator;
                if (evaluator.getClass().equals(SeverityPolicyEvaluator.class) ||
                        evaluator.getClass().equals(CwePolicyEvaluator.class) ||
                        evaluator.getClass().equals(VulnerabilityIdPolicyEvaluator.class)) {
                    policyConditionViolationsFromEvaluator = evaluator.evaluate(policy, component, vulnerabilities);
                } else {
                    policyConditionViolationsFromEvaluator = evaluator.evaluate(policy, component);
                }
                if (!policyConditionViolationsFromEvaluator.isEmpty()) {
                    policyConditionViolations.addAll(policyConditionViolationsFromEvaluator);
                    policyConditionsViolated += (int) policyConditionViolationsFromEvaluator.stream()
                            .map(pcv -> pcv.getPolicyCondition().getId())
                            .sorted()
                            .distinct()
                            .count();
                }
            }
            List<PolicyViolation> result = addToPolicyViolation(qm, policy, policyConditionsViolated, policyConditionViolations);
            if (!result.isEmpty())
                policyViolations.addAll(result);
        }
        qm.reconcilePolicyViolations(component, policyViolations);
        for (final PolicyViolation pv : qm.getAllPolicyViolations(component)) {
            if (existingPolicyViolations.stream().noneMatch(existingViolation -> existingViolation.getId() == pv.getId())) {
                NotificationUtil.analyzeNotificationCriteria(qm, pv);
            }
        }
        return policyViolations;
    }

    private List<PolicyViolation> addToPolicyViolation(QueryManager qm, Policy policy, int policyConditionsViolated, List<PolicyConditionViolation> policyConditionViolations) {
        if (policy.getOperator() == Policy.Operator.ANY) {
            if (policyConditionsViolated > 0) {
                return createPolicyViolations(qm, policyConditionViolations);
            }
        } else if (Policy.Operator.ALL == policy.getOperator() && policyConditionsViolated == policy.getPolicyConditions().size()) {
            return createPolicyViolations(qm, policyConditionViolations);
        }
        return Collections.emptyList();
    }

    private List<PolicyViolation> createPolicyViolations(final QueryManager qm, final List<PolicyConditionViolation> pcvList) {
        final List<PolicyViolation> policyViolations = new ArrayList<>();
        for (PolicyConditionViolation pcv : pcvList) {
            final PolicyViolation pv = new PolicyViolation();
            pv.setComponent(pcv.getComponent());
            pv.setPolicyCondition(pcv.getPolicyCondition());
            pv.setType(determineViolationType(pcv.getPolicyCondition().getSubject()));
            pv.setTimestamp(new Date());
            policyViolations.add(qm.addPolicyViolationIfNotExist(pv));
        }
        return policyViolations;
    }

    public PolicyViolation.Type determineViolationType(final PolicyCondition.Subject subject) {
        if (subject == null) {
            return null;
        }
        return switch (subject) {
            case CWE, SEVERITY, VULNERABILITY_ID -> PolicyViolation.Type.SECURITY;
            case AGE, COORDINATES, PACKAGE_URL, CPE, SWID_TAGID, COMPONENT_HASH, VERSION ->
                    PolicyViolation.Type.OPERATIONAL;
            case LICENSE, LICENSE_GROUP -> PolicyViolation.Type.LICENSE;
            case EXPRESSION -> null; // TODO: Just here to satisfy the switch exhaustiveness
        };
    }

    private static List<Component> fetchNextComponentsPage(final PersistenceManager pm, final Project project,
                                                           final Long lastId) {
        final Query<Component> query = pm.newQuery(Component.class);
        try {
            if (lastId == null) {
                query.setFilter("project == :project");
                query.setParameters(project);
            } else {
                query.setFilter("project == :project && id < :lastId");
                query.setParameters(project, lastId);
            }
            query.setOrdering("id DESC");
            query.setRange(0, 500);
            return List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }
    }

}