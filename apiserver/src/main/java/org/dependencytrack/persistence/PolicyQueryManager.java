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
package org.dependencytrack.persistence;

import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisComment;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.util.DateUtil;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.dependencytrack.util.PersistenceUtil.assertPersistent;
import static org.dependencytrack.util.PersistenceUtil.assertPersistentAll;

final class PolicyQueryManager extends QueryManager implements IQueryManager {

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    PolicyQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    PolicyQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a List of all Policy objects.
     * @return a List of all Policy objects
     */
    public PaginatedResult getPolicies() {
        final Query<Policy> query = pm.newQuery(Policy.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:filter)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a List of all Policy objects.
     * This method if designed NOT to provide paginated results.
     * @return a List of all Policy objects
     */
    public List<Policy> getAllPolicies() {
        final Query<Policy> query = pm.newQuery(Policy.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        return query.executeList();
    }

    /**
     * Returns a policy by it's name.
     * @param name the name of the policy (required)
     * @return a Policy object, or null if not found
     */
    public Policy getPolicy(final String name) {
        final Query<Policy> query = pm.newQuery(Policy.class, "name == :name");
        query.setRange(0, 1);
        return singleResult(query.execute(name));
    }

    /**
     * Creates a new Policy.
     * @param name the name of the policy to create
     * @param operator the operator
     * @param violationState the violation state
     * @return the created Policy
     */
    public Policy createPolicy(String name, Policy.Operator operator, Policy.ViolationState violationState,
                               boolean onlyLatestProjectVersion) {
        final Policy policy = new Policy();
        policy.setName(name);
        policy.setOperator(operator);
        policy.setViolationState(violationState);
        policy.setOnlyLatestProjectVersion(onlyLatestProjectVersion);
        return persist(policy);
    }

    /**
     * Creates a policy condition for the specified Project.
     * @return the created PolicyCondition object
     */
    public PolicyCondition createPolicyCondition(final Policy policy, final PolicyCondition.Subject subject,
                                                 final PolicyCondition.Operator operator, final String value) {
        return createPolicyCondition(policy, subject, operator, value, null);
    }

    /**
     * Creates a policy condition for the specified Project.
     * @return the created PolicyCondition object
     */
    public PolicyCondition createPolicyCondition(final Policy policy, final PolicyCondition.Subject subject,
                                                 final PolicyCondition.Operator operator, final String value,
                                                 final PolicyViolation.Type violationType) {
        final PolicyCondition pc = new PolicyCondition();
        pc.setPolicy(policy);
        pc.setSubject(subject);
        if (subject == PolicyCondition.Subject.EXPRESSION) {
            pc.setOperator(PolicyCondition.Operator.MATCHES);
        } else {
            pc.setOperator(operator);
        }
        pc.setValue(value);
        pc.setViolationType(violationType);
        return persist(pc);
    }

    /**
     * Updates a policy condition.
     * @return the updated PolicyCondition object
     */
    public PolicyCondition updatePolicyCondition(final PolicyCondition policyCondition) {
        final PolicyCondition pc = getObjectByUuid(PolicyCondition.class, policyCondition.getUuid());
        pc.setSubject(policyCondition.getSubject());
        if (policyCondition.getSubject() == PolicyCondition.Subject.EXPRESSION) {
            pc.setOperator(PolicyCondition.Operator.MATCHES);
        } else {
            pc.setOperator(policyCondition.getOperator());
        }
        pc.setValue(policyCondition.getValue());
        pc.setViolationType(policyCondition.getViolationType());
        return persist(pc);
    }

    /**
     * Returns a List of all Policy objects.
     * This method if designed NOT to provide paginated results.
     * @return a List of all Policy objects
     */
    public List<PolicyViolation> getAllPolicyViolations() {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class);
        if (orderBy == null) {
            query.setOrdering("timestamp desc, project.name, project.version, component.name, component.version");
        }
        return query.executeList();
    }

    /**
     * Returns a List of all Policy objects.
     * This method if designed NOT to provide paginated results.
     * @return a List of all Policy objects
     */
    @SuppressWarnings("unchecked")
    public List<PolicyViolation> getAllPolicyViolations(final PolicyCondition policyCondition) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "policyCondition.id == :pid");
        if (orderBy == null) {
            query.setOrdering("timestamp desc, project.name, project.version, component.name, component.version");
        }
        return (List<PolicyViolation>)query.execute(policyCondition.getId());
    }

    /**
     * Returns a List of all {@link PolicyViolation}s for a specific component.
     * @param component The component to fetch {@link PolicyViolation}s for
     * @return a List of {@link PolicyViolation}s
     */
    public List<PolicyViolation> getAllPolicyViolations(final Component component) {
        return getAllPolicyViolations(component, true);
    }

    /**
     * Returns a List of all {@link PolicyViolation}s for a specific component.
     * @param component The component to fetch {@link PolicyViolation}s for
     * @param includeSuppressed Whether to include suppressed violations or not
     * @return a List of {@link PolicyViolation}s
     */
    public List<PolicyViolation> getAllPolicyViolations(final Component component, final boolean includeSuppressed) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class);
        if (includeSuppressed) {
            query.setFilter("component.id == :cid");
        } else {
            query.setFilter("component.id == :cid && suppressions == 0");
            query.declareVariables("long suppressions");

            // For a given policy violation, check whether an analysis exists that suppresses it.
            // The query will return either 0 (no analysis exists or not suppressed) or 1 (suppressed).
            final Query<ViolationAnalysis> subQuery = pm.newQuery(ViolationAnalysis.class);
            subQuery.setFilter("policyViolation == :policyViolation && suppressed == true");
            subQuery.setResult("count(id)");
            query.addSubquery(subQuery, "long suppressions", null, "this");
        }
        if (orderBy == null) {
            query.setOrdering("timestamp desc, project.name, project.version, component.name, component.version");
        }
        query.setParameters(component.getId());
        return query.executeList();
    }

    /**
     * clones a policy violation
     * @param sourcePolicyViolation the policy violation to clone
     * @param destinationComponent the corresponding component
     */
    public PolicyViolation clonePolicyViolation(PolicyViolation sourcePolicyViolation, Component destinationComponent){
        //cloning PolicyViolation
        final PolicyViolation policyViolation = new PolicyViolation();
        policyViolation.setType(sourcePolicyViolation.getType());
        policyViolation.setComponent(destinationComponent);
        policyViolation.setPolicyCondition(sourcePolicyViolation.getPolicyCondition());
        policyViolation.setTimestamp(sourcePolicyViolation.getTimestamp());
        policyViolation.setText(sourcePolicyViolation.getText());
        policyViolation.setType(sourcePolicyViolation.getType());
        //cloning ViolatioAnalysis
        ViolationAnalysis violationAnalysis = cloneViolationAnalysis(destinationComponent, sourcePolicyViolation);
        //cloning ViolationAnalysisComments
        List<ViolationAnalysisComment> comments = cloneViolationAnalysisComments(sourcePolicyViolation, violationAnalysis);
        if(comments != null){
            violationAnalysis.setAnalysisComments(comments);
        }
        policyViolation.setAnalysis(violationAnalysis); 
        policyViolation.getAnalysis().setPolicyViolation(policyViolation);
        policyViolation.setUuid(sourcePolicyViolation.getUuid());
        return policyViolation;
}
    /**
     * Returns a List of all Policy objects for a specific component.
     * This method if designed NOT to provide paginated results.
     * @return a List of all Policy objects
     */
    @SuppressWarnings("unchecked")
    public List<PolicyViolation> getAllPolicyViolations(final Project project) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "project.id == :pid");
        if (orderBy == null) {
            query.setOrdering("timestamp desc, component.name, component.version");
        }
        return (List<PolicyViolation>)query.execute(project.getId());
    }

    /**
     * Returns a List of all Policy violations for a specific project.
     * @param project the project to retrieve violations for
     * @return a List of all Policy violations
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getPolicyViolations(final Project project, boolean includeSuppressed) {
        PaginatedResult result;
        final String queryFilter = includeSuppressed ? "project.id == :pid" : "project.id == :pid && (analysis.suppressed == false || analysis.suppressed == null)";
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class);
        if (orderBy == null) {
            query.setOrdering("timestamp desc, component.name, component.version");
        }
        if (filter != null) {
            query.setFilter(queryFilter + " && (policyCondition.policy.name.toLowerCase().matches(:filter) || component.name.toLowerCase().matches(:filter))");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            result = execute(query, project.getId(), filterString);
        } else {
            query.setFilter(queryFilter);
            result = execute(query, project.getId());
        }
        for (final PolicyViolation violation: result.getList(PolicyViolation.class)) {
            violation.getPolicyCondition().getPolicy(); // force policy to ne included since its not the default
            violation.getComponent().getResolvedLicense(); // force resolved license to ne included since its not the default
            violation.setAnalysis(getViolationAnalysis(violation.getComponent(), violation)); // Include the violation analysis by default
        }
        return result;
    }

    /**
     * Returns a List of all Policy violations for a specific component.
     * @param component the component to retrieve violations for
     * @return a List of all Policy violations
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getPolicyViolations(final Component component, boolean includeSuppressed) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class);
        if (includeSuppressed) {
            query.setFilter("component.id == :cid");
        } else {
            query.setFilter("component.id == :cid && (analysis.suppressed == false || analysis.suppressed == null)");
        }
        if (orderBy == null) {
            query.setOrdering("timestamp desc");
        }
        final PaginatedResult result = execute(query, component.getId());
        for (final PolicyViolation violation: result.getList(PolicyViolation.class)) {
            violation.getPolicyCondition().getPolicy(); // force policy to ne included since its not the default
            violation.getComponent().getResolvedLicense(); // force resolved license to ne included since its not the default
            violation.setAnalysis(getViolationAnalysis(violation.getComponent(), violation)); // Include the violation analysis by default
        }
        return result;
    }

    /**
     * Returns a List of all Policy violations for the entire portfolio filtered by ACL and other optional filters.
     * @return a List of all Policy violations
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getPolicyViolations(boolean includeSuppressed, boolean showInactive, Map<String, String> filters) {
        final PaginatedResult result;
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class);
        final Map<String, Object> params = new HashMap<>();
        final List<String> filterCriteria = new ArrayList<>();
        if (!includeSuppressed) {
            filterCriteria.add("(analysis.suppressed == false || analysis.suppressed == null)");
        }
        if (!showInactive) {
            filterCriteria.add("(project.inactiveSince == null)");
        }
        processViolationsFilters(filters, params, filterCriteria);
        if (orderBy == null) {
            query.setOrdering("timestamp desc, project.name, project.version, component.name, component.version");
        }
        final String queryFilter = String.join(" && ", filterCriteria);
        preprocessACLs(query, queryFilter, params);
        result = execute(query, params);
        for (final PolicyViolation violation: result.getList(PolicyViolation.class)) {
            violation.getPolicyCondition().getPolicy(); // force policy to be included since it's not the default
            violation.getComponent().getResolvedLicense(); // force resolved license to be included since it's not the default
            violation.setAnalysis(getViolationAnalysis(violation.getComponent(), violation)); // Include the violation analysis by default
        }
        return result;
    }

    /**
     * clones a ViolationAnalysis
     * @param destinationComponent the destinationComponent
     * @param sourcePolicyViolation the PolicyViolation to clone from
     * @return the cloned violationAnalysis
     */
    public ViolationAnalysis cloneViolationAnalysis(Component destinationComponent, PolicyViolation sourcePolicyViolation){
        ViolationAnalysis violationAnalysis = new ViolationAnalysis();
        violationAnalysis.setComponent(destinationComponent);
        if(sourcePolicyViolation.getAnalysis() != null){
            violationAnalysis.setSuppressed(sourcePolicyViolation.getAnalysis().isSuppressed());
            violationAnalysis.setViolationAnalysisState(sourcePolicyViolation.getAnalysis().getAnalysisState());
        } else {
            violationAnalysis.setViolationAnalysisState(ViolationAnalysisState.NOT_SET);
        }
        return violationAnalysis;
    }

    /**
     * Returns a ViolationAnalysis for the specified Component and PolicyViolation.
     * @param component the Component
     * @param policyViolation the PolicyViolation
     * @return a ViolationAnalysis object, or null if not found
     */
    public ViolationAnalysis getViolationAnalysis(Component component, PolicyViolation policyViolation) {
        final Query<ViolationAnalysis> query = pm.newQuery(ViolationAnalysis.class, "component == :component && policyViolation == :policyViolation");
        query.setRange(0, 1);
        return singleResult(query.execute(component, policyViolation));
    }

    /**
     * Documents a new violation analysis. Creates a new ViolationAnalysis object if one doesn't already exists and appends
     * the specified comment along with a timestamp in the ViolationAnalysisComment trail.
     * @param component the Component
     * @param policyViolation the PolicyViolation
     * @return a ViolationAnalysis object
     */
    public ViolationAnalysis makeViolationAnalysis(Component component, PolicyViolation policyViolation,
                                                   ViolationAnalysisState violationAnalysisState, Boolean isSuppressed) {
        if (violationAnalysisState == null) {
            violationAnalysisState = ViolationAnalysisState.NOT_SET;
        }
        ViolationAnalysis violationAnalysis = getViolationAnalysis(component, policyViolation);
        if (violationAnalysis == null) {
            violationAnalysis = new ViolationAnalysis();
            violationAnalysis.setComponent(component);
            violationAnalysis.setPolicyViolation(policyViolation);
        }
        if (isSuppressed != null) {
            violationAnalysis.setSuppressed(isSuppressed);
        }
        violationAnalysis.setViolationAnalysisState(violationAnalysisState);
        violationAnalysis = persist(violationAnalysis);
        return getViolationAnalysis(violationAnalysis.getComponent(), violationAnalysis.getPolicyViolation());
    }


    /**
     * clones ViolationAnalysisComments
     * @param sourcePolicyViolation the source PolicyViolation
     * @param violationAnalysis the ViolationAnalysis to clone from
     * @return the cloned ViolationAnalysisComments
     */
    public List<ViolationAnalysisComment> cloneViolationAnalysisComments(PolicyViolation sourcePolicyViolation, ViolationAnalysis violationAnalysis){
        List<ViolationAnalysisComment> comments = new ArrayList<ViolationAnalysisComment>();
        if(sourcePolicyViolation.getAnalysis() != null && sourcePolicyViolation.getAnalysis().getAnalysisComments() != null){
            for(ViolationAnalysisComment c : sourcePolicyViolation.getAnalysis().getAnalysisComments()){
                ViolationAnalysisComment comment = new ViolationAnalysisComment();
                comment.setViolationAnalysis(violationAnalysis);
                comment.setComment(c.getComment());
                comment.setCommenter(c.getCommenter());
                comment.setTimestamp(c.getTimestamp());
                comments.add(comment);
            }
        }

        return comments;
    }



    /**
     * Adds a new violation analysis comment to the specified violation analysis.
     * @param violationAnalysis the violation analysis object to add a comment to
     * @param comment the comment to make
     * @param commenter the name of the principal who wrote the comment
     * @return a new ViolationAnalysisComment object
     */
    public ViolationAnalysisComment makeViolationAnalysisComment(ViolationAnalysis violationAnalysis, String comment, String commenter) {
        if (violationAnalysis == null || comment == null) {
            return null;
        }
        final ViolationAnalysisComment violationAnalysisComment = new ViolationAnalysisComment();
        violationAnalysisComment.setViolationAnalysis(violationAnalysis);
        violationAnalysisComment.setTimestamp(new Date());
        violationAnalysisComment.setComment(comment);
        violationAnalysisComment.setCommenter(commenter);
        return persist(violationAnalysisComment);
    }

    /**
     * Deleted all violation analysis and comments associated for the specified Component.
     * @param component the Component to delete violation analysis for
     */
    void deleteViolationAnalysisTrail(Component component) {
        final Query<ViolationAnalysis> query = pm.newQuery(ViolationAnalysis.class, "component == :component");
        query.deletePersistentAll(component);
    }

    /**
     * Deleted all violation analysis and comments associated for the specified Project.
     * @param project the Project to delete violation analysis for
     */
    void deleteViolationAnalysisTrail(Project project) {
        final Query<ViolationAnalysis> query = pm.newQuery(ViolationAnalysis.class, "project == :project");
        query.deletePersistentAll(project);
    }

    /**
     * Deleted all violation analysis and comments associated for the specified Policy Condition.
     * @param policyViolation policy violation to delete violation analysis for
     */
    private void deleteViolationAnalysisTrail(PolicyViolation policyViolation) {
        final Query<ViolationAnalysis> query = pm.newQuery(ViolationAnalysis.class, "policyViolation.id == :pid");
        query.deletePersistentAll(policyViolation.getId());
    }

    /**
     * Returns a List of all LicenseGroup objects.
     * @return a List of all LicenseGroup objects
     */
    public PaginatedResult getLicenseGroups() {
        final Query<LicenseGroup> query = pm.newQuery(LicenseGroup.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:filter)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a license group by it's name.
     * @param name the name of the license group (required)
     * @return a LicenseGroup object, or null if not found
     */
    public LicenseGroup getLicenseGroup(final String name) {
        final Query<LicenseGroup> query = pm.newQuery(LicenseGroup.class, "name == :name");
        query.setRange(0, 1);
        return singleResult(query.execute(name));
    }

    /**
     * Creates a new LicenseGroup.
     * @param name the name of the license group to create
     * @return the created LicenseGroup
     */
    public LicenseGroup createLicenseGroup(String name) {
        final LicenseGroup licenseGroup = new LicenseGroup();
        licenseGroup.setName(name);
        return persist(licenseGroup);
    }

    /**
     * Determines if the specified LicenseGroup contains the specified License.
     * @param lg the LicenseGroup to query
     * @param license the License to query for
     * @return true if License is part of LicenseGroup, false if not
     */
    public boolean doesLicenseGroupContainLicense(final LicenseGroup lg, final License license) {
        final License l = getObjectById(License.class, license.getId());
        final Query<LicenseGroup> query = pm.newQuery(LicenseGroup.class, "id == :id && licenses.contains(:license)");
        query.setRange(0, 1);
        return singleResult(query.execute(lg.getId(), l)) != null;
    }

    /**
     * Deletes a {@link Policy}, including all related {@link PolicyViolation}s and {@link PolicyCondition}s.
     * @param policy the {@link Policy} to delete
     */
    public void deletePolicy(final Policy policy) {
        for (final PolicyCondition condition : policy.getPolicyConditions()) {
            deletePolicyCondition(condition);
        }
        delete(policy);
    }

    /**
     * Deleted all PolicyViolation associated for the specified Component.
     * @param component the Component to delete PolicyViolation for
     */
    void deletePolicyViolations(Component component) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "component == :component");
        query.deletePersistentAll(component);
    }

    /**
     * Deleted all PolicyViolation associated for the specified Project.
     * @param project the Project to delete PolicyViolation for
     */
    public void deletePolicyViolations(final Project project) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "project == :project");
        query.deletePersistentAll(project);
    }

    /**
     * Deleted all {@link PolicyViolation}s associated with the specified {@link Component}.
     *
     * @param component The {@link Component} to delete {@link PolicyViolation}s for
     * @since 5.0.0
     */
    public void deletePolicyViolationsOfComponent(final Component component) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "component == :component");
        query.deletePersistentAll(component);
    }

    /**
     * Deleted all PolicyViolation associated for the specified PolicyCondition.
     * @param policyCondition the PolicyCondition to delete PolicyViolation for
     */
    public void deletePolicyCondition(PolicyCondition policyCondition) {
        final List<PolicyViolation> violations = getAllPolicyViolations(policyCondition);
        for (PolicyViolation violation: violations) {
            deleteViolationAnalysisTrail(violation);
        }
        delete(violations);
        delete(policyCondition);
    }

    /**
     * Removes all associations with a given {@link Project} from all {@link Policy}s.
     * @param project The {@link Project} to remove from policies
     */
    public void removeProjectFromPolicies(final Project project) {
        final Query<Policy> query = pm.newQuery(Policy.class, "projects.contains(:project)");
        try {
            query.setParameters(project);

            for (final Policy policy : query.executeList()) {
                policy.getProjects().remove(project);

                if (!pm.currentTransaction().isActive()) {
                    persist(policy);
                }
            }
        } finally {
            query.closeAll();
        }
    }

    /**
     * Returns the number of audited policy violations of a given type for a component.
     * @param component The {@link Component} to retrieve audit counts for
     * @param type The {@link PolicyViolation.Type} to retrieve audit counts for
     * @return The total number of audited {@link PolicyViolation}s for the {@link Component}
     */
    public long getAuditedCount(final Component component, final PolicyViolation.Type type) {
        final Query<ViolationAnalysis> query = pm.newQuery(ViolationAnalysis.class);
        query.setFilter("component == :component && policyViolation.type == :type && analysisState != null && analysisState != :notSet");
        return getCount(query, component, type, ViolationAnalysisState.NOT_SET);
    }

    /**
     * @since 4.12.3
     */
    @Override
    public boolean bind(final Policy policy, final Collection<Tag> tags, final boolean keepExisting) {
        assertPersistent(policy, "policy must be persistent");
        assertPersistentAll(tags, "tags must be persistent");
        return callInTransaction(() -> {
            boolean modified = false;

            if (!keepExisting) {
                final Iterator<Tag> existingTagsIterator = policy.getTags().iterator();
                while (existingTagsIterator.hasNext()) {
                    final Tag existingTag = existingTagsIterator.next();
                    if (!tags.contains(existingTag)) {
                        existingTagsIterator.remove();
                        existingTag.getPolicies().remove(policy);
                        modified = true;
                    }
                }
            }

            for (final Tag tag : tags) {
                if (!policy.getTags().contains(tag)) {
                    policy.getTags().add(tag);
                    if (tag.getPolicies() == null) {
                        tag.setPolicies(new HashSet<>(Set.of(policy)));
                    } else {
                        tag.getPolicies().add(policy);
                    }
                    modified = true;
                }
            }
            return modified;
        });
    }

    /**
     * @since 4.12.0
     */
    @Override
    public boolean bind(final Policy policy, final Collection<Tag> tags) {
        return bind(policy, tags, /* keepExisting */ false);
    }

    private void processViolationsFilters(Map<String, String> filters, Map<String, Object> params, List<String> filterCriteria) {
        for (Map.Entry<String, String> filter : filters.entrySet()) {
            switch (filter.getKey()) {
                case "violationState" -> processArrayFilter(params, filterCriteria, "violationState", filter.getValue(), "policyCondition.policy.violationState");
                case "riskType" -> processArrayFilter(params, filterCriteria, "riskType", filter.getValue(), "type");
                case "policy" -> processArrayFilter(params, filterCriteria, "policy", filter.getValue(), "policyCondition.policy.uuid");
                case "analysisState" -> processArrayFilter(params, filterCriteria, "analysisState", filter.getValue(), "analysis.analysisState");
                case "occurredOnDateFrom" -> processDateFilter(params, filterCriteria, "occuredOnDateFrom", filter.getValue(), true);
                case "occurredOnDateTo" -> processDateFilter(params, filterCriteria, "occuredOnDateTo", filter.getValue(), false);
                case "textSearchField" -> processInputFilter(params, filterCriteria, "textInput", filter.getValue(), filters.get("textSearchInput"));
            }
        }
    }

    private void processArrayFilter(Map<String, Object> params, List<String> filterCriteria, String paramName, String filter, String column) {
        if (filter != null && !filter.isEmpty()) {
            StringBuilder filterBuilder = new StringBuilder("(");
            String[] arrayFilter = filter.split(",");
            for (int i = 0, arrayFilterLength = arrayFilter.length; i < arrayFilterLength; i++) {
                filterBuilder.append(column).append(" == :").append(paramName).append(i);
                switch (paramName) {
                    case "violationState" -> params.put(paramName + i, Policy.ViolationState.valueOf(arrayFilter[i]));
                    case "riskType" -> params.put(paramName + i, PolicyViolation.Type.valueOf(arrayFilter[i]));
                    case "policy" -> params.put(paramName + i, UUID.fromString(arrayFilter[i]));
                    case "analysisState" -> {
                        if (arrayFilter[i].equals("NOT_SET")) {
                            filterBuilder.append(" || ").append(column).append(" == null");
                        }
                        params.put(paramName + i, ViolationAnalysisState.valueOf(arrayFilter[i]));
                    }
                }
                if (i < arrayFilterLength - 1) {
                    filterBuilder.append(" || ");
                }
            }
            filterBuilder.append(")");
            filterCriteria.add(filterBuilder.toString());
        }
    }

    private void processDateFilter(Map<String, Object> params, List<String> filterCriteria, String paramName, String filter, boolean fromValue) {
        if (filter != null && !filter.isEmpty()) {
            params.put(paramName, DateUtil.fromISO8601(filter + (fromValue ? "T00:00:00" : "T23:59:59")));
            filterCriteria.add("(timestamp " + (fromValue ? ">= :" : "<= :") + paramName + ")");
        }
    }

    private void processInputFilter(Map<String, Object> params, List<String> filterCriteria, String paramName, String filter, String input) {
        if (filter != null && !filter.isEmpty() && input != null && !input.isEmpty()) {
            StringBuilder filterBuilder = new StringBuilder("(");
            String[] inputFilter = filter.split(",");
            for (int i = 0, inputFilterLength = inputFilter.length; i < inputFilterLength; i++) {
                switch (inputFilter[i].toLowerCase()) {
                    case "policy_name" -> filterBuilder.append("policyCondition.policy.name");
                    case "component" -> filterBuilder.append("component.name");
                    case "license" -> filterBuilder.append("component.resolvedLicense.licenseId.toLowerCase().matches(:").append(paramName).append(") || component.license");
                    case "project_name" -> filterBuilder.append("project.name.toLowerCase().matches(:").append(paramName).append(") || project.version");
                }
                filterBuilder.append(".toLowerCase().matches(:").append(paramName).append(")");
                if (i < inputFilterLength - 1) {
                    filterBuilder.append(" || ");
                }
            }
            params.put(paramName, ".*" + input.toLowerCase() + ".*");
            filterBuilder.append(")");
            filterCriteria.add(filterBuilder.toString());
        }
    }

}
