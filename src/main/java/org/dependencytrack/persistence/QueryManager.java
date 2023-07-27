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
package org.dependencytrack.persistence;

import alpine.common.util.BooleanUtil;
import alpine.model.ApiKey;
import alpine.model.ConfigProperty;
import alpine.model.Team;
import alpine.model.UserPrincipal;
import alpine.notification.NotificationLevel;
import alpine.persistence.AlpineQueryManager;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import com.github.packageurl.PackageURL;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import org.apache.commons.lang3.ClassUtils;
import org.datanucleus.PropertyNames;
import org.datanucleus.api.jdo.JDOQuery;
import org.dependencytrack.model.AffectedVersionAttribution;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Cpe;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vex;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisComment;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.PublisherClass;
import org.hyades.proto.vulnanalysis.v1.ScanResult;
import org.hyades.proto.vulnanalysis.v1.ScanStatus;
import org.hyades.proto.vulnanalysis.v1.ScannerResult;

import javax.jdo.FetchPlan;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.Transaction;
import java.security.Principal;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.function.Supplier;

import static org.hyades.proto.vulnanalysis.v1.ScanStatus.SCAN_STATUS_FAILED;

/**
 * This QueryManager provides a concrete extension of {@link AlpineQueryManager} by
 * providing methods that operate on the Dependency-Track specific models.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@SuppressWarnings({"UnusedReturnValue", "unused"})
public class QueryManager extends AlpineQueryManager {

    private AlpineRequest request;
    private BomQueryManager bomQueryManager;
    private ComponentQueryManager componentQueryManager;
    private FindingsQueryManager findingsQueryManager;
    private LicenseQueryManager licenseQueryManager;
    private MetricsQueryManager metricsQueryManager;
    private NotificationQueryManager notificationQueryManager;
    private PolicyQueryManager policyQueryManager;
    private ProjectQueryManager projectQueryManager;
    private RepositoryQueryManager repositoryQueryManager;
    private ServiceComponentQueryManager serviceComponentQueryManager;
    private VexQueryManager vexQueryManager;
    private VulnerabilityQueryManager vulnerabilityQueryManager;
    private VulnerableSoftwareQueryManager vulnerableSoftwareQueryManager;
    private WorkflowStateQueryManager workflowStateQueryManager;

    private TagQueryManager tagQueryManager;

    /**
     * Default constructor.
     */
    public QueryManager() {
        super();
        disableL2Cache();
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param pm a PersistenceManager object
     */
    public QueryManager(final PersistenceManager pm) {
        super(pm);
        disableL2Cache();
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param request an AlpineRequest object
     */
    public QueryManager(final AlpineRequest request) {
        super(request);
        disableL2Cache();
        this.request = request;
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param request an AlpineRequest object
     */
    public QueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
        disableL2Cache();
        this.request = request;
    }

    /**
     * Lazy instantiation of ProjectQueryManager.
     *
     * @return a ProjectQueryManager object
     */
    private ProjectQueryManager getProjectQueryManager() {
        if (projectQueryManager == null) {
            projectQueryManager = (request == null) ? new ProjectQueryManager(getPersistenceManager()) : new ProjectQueryManager(getPersistenceManager(), request);
        }
        return projectQueryManager;
    }

    /**
     * Lazy instantiation of TagQueryManager.
     *
     * @return a TagQueryManager object
     */
    private TagQueryManager getTagQueryManager() {
        if (tagQueryManager == null) {
            tagQueryManager = (request == null) ? new TagQueryManager(getPersistenceManager()) : new TagQueryManager(getPersistenceManager(), request);
        }
        return tagQueryManager;
    }

    /**
     * Lazy instantiation of ComponentQueryManager.
     *
     * @return a ComponentQueryManager object
     */
    private ComponentQueryManager getComponentQueryManager() {
        if (componentQueryManager == null) {
            componentQueryManager = (request == null) ? new ComponentQueryManager(getPersistenceManager()) : new ComponentQueryManager(getPersistenceManager(), request);
        }
        return componentQueryManager;
    }

    /**
     * Lazy instantiation of LicenseQueryManager.
     *
     * @return a LicenseQueryManager object
     */
    private LicenseQueryManager getLicenseQueryManager() {
        if (licenseQueryManager == null) {
            licenseQueryManager = (request == null) ? new LicenseQueryManager(getPersistenceManager()) : new LicenseQueryManager(getPersistenceManager(), request);
        }
        return licenseQueryManager;
    }

    /**
     * Lazy instantiation of BomQueryManager.
     *
     * @return a BomQueryManager object
     */
    private BomQueryManager getBomQueryManager() {
        if (bomQueryManager == null) {
            bomQueryManager = (request == null) ? new BomQueryManager(getPersistenceManager()) : new BomQueryManager(getPersistenceManager(), request);
        }
        return bomQueryManager;
    }

    /**
     * Lazy instantiation of VexQueryManager.
     *
     * @return a VexQueryManager object
     */
    private VexQueryManager getVexQueryManager() {
        if (vexQueryManager == null) {
            vexQueryManager = (request == null) ? new VexQueryManager(getPersistenceManager()) : new VexQueryManager(getPersistenceManager(), request);
        }
        return vexQueryManager;
    }

    /**
     * Lazy instantiation of PolicyQueryManager.
     *
     * @return a PolicyQueryManager object
     */
    private PolicyQueryManager getPolicyQueryManager() {
        if (policyQueryManager == null) {
            policyQueryManager = (request == null) ? new PolicyQueryManager(getPersistenceManager()) : new PolicyQueryManager(getPersistenceManager(), request);
        }
        return policyQueryManager;
    }

    /**
     * Lazy instantiation of VulnerabilityQueryManager.
     *
     * @return a VulnerabilityQueryManager object
     */
    private VulnerabilityQueryManager getVulnerabilityQueryManager() {
        if (vulnerabilityQueryManager == null) {
            vulnerabilityQueryManager = (request == null) ? new VulnerabilityQueryManager(getPersistenceManager()) : new VulnerabilityQueryManager(getPersistenceManager(), request);
        }
        return vulnerabilityQueryManager;
    }

    /**
     * Lazy instantiation of VulnerableSoftwareQueryManager.
     *
     * @return a VulnerableSoftwareQueryManager object
     */
    private VulnerableSoftwareQueryManager getVulnerableSoftwareQueryManager() {
        if (vulnerableSoftwareQueryManager == null) {
            vulnerableSoftwareQueryManager = (request == null) ? new VulnerableSoftwareQueryManager(getPersistenceManager()) : new VulnerableSoftwareQueryManager(getPersistenceManager(), request);
        }
        return vulnerableSoftwareQueryManager;
    }

    /**
     * Lazy instantiation of ServiceComponentQueryManager.
     *
     * @return a ServiceComponentQueryManager object
     */
    private ServiceComponentQueryManager getServiceComponentQueryManager() {
        if (serviceComponentQueryManager == null) {
            serviceComponentQueryManager = (request == null) ? new ServiceComponentQueryManager(getPersistenceManager()) : new ServiceComponentQueryManager(getPersistenceManager(), request);
        }
        return serviceComponentQueryManager;
    }

    /**
     * Lazy instantiation of FindingsQueryManager.
     *
     * @return a FindingsQueryManager object
     */
    private FindingsQueryManager getFindingsQueryManager() {
        if (findingsQueryManager == null) {
            findingsQueryManager = (request == null) ? new FindingsQueryManager(getPersistenceManager()) : new FindingsQueryManager(getPersistenceManager(), request);
        }
        return findingsQueryManager;
    }

    /**
     * Lazy instantiation of MetricsQueryManager.
     *
     * @return a MetricsQueryManager object
     */
    private MetricsQueryManager getMetricsQueryManager() {
        if (metricsQueryManager == null) {
            metricsQueryManager = (request == null) ? new MetricsQueryManager(getPersistenceManager()) : new MetricsQueryManager(getPersistenceManager(), request);
        }
        return metricsQueryManager;
    }

    /**
     * Lazy instantiation of RepositoryQueryManager.
     *
     * @return a RepositoryQueryManager object
     */
    private RepositoryQueryManager getRepositoryQueryManager() {
        if (repositoryQueryManager == null) {
            repositoryQueryManager = (request == null) ? new RepositoryQueryManager(getPersistenceManager()) : new RepositoryQueryManager(getPersistenceManager(), request);
        }
        return repositoryQueryManager;
    }

    /**
     * Lazy instantiation of NotificationQueryManager.
     *
     * @return a NotificationQueryManager object
     */
    private NotificationQueryManager getNotificationQueryManager() {
        if (notificationQueryManager == null) {
            notificationQueryManager = (request == null) ? new NotificationQueryManager(getPersistenceManager()) : new NotificationQueryManager(getPersistenceManager(), request);
        }
        return notificationQueryManager;
    }

    private WorkflowStateQueryManager getWorkflowStateQueryManager() {
        if (workflowStateQueryManager == null) {
            workflowStateQueryManager = (request == null) ? new WorkflowStateQueryManager(getPersistenceManager()) : new WorkflowStateQueryManager(getPersistenceManager(), request);
        }
        return workflowStateQueryManager;
    }

    /**
     * Get the IDs of the {@link Team}s a given {@link Principal} is a member of.
     *
     * @return A {@link Set} of {@link Team} IDs
     */
    protected Set<Long> getTeamIds(final Principal principal) {
        final Set<Long> principalTeamIds = new HashSet<>();

        if (principal instanceof final UserPrincipal userPrincipal
                && userPrincipal.getTeams() != null) {
            for (final Team userInTeam : userPrincipal.getTeams()) {
                principalTeamIds.add(userInTeam.getId());
            }
        } else if (principal instanceof final ApiKey apiKey
                && apiKey.getTeams() != null) {
            for (final Team userInTeam : apiKey.getTeams()) {
                principalTeamIds.add(userInTeam.getId());
            }
        }

        return principalTeamIds;
    }

    private void disableL2Cache() {
        pm.setProperty(PropertyNames.PROPERTY_CACHE_L2_TYPE, "none");
    }

    /**
     * Disables the second level cache for this {@link QueryManager} instance.
     * <p>
     * Disabling the L2 cache is useful in situations where large amounts of objects
     * are created or updated in close succession, and it's unlikely that they'll be
     * accessed again anytime soon. Keeping those objects in cache would unnecessarily
     * blow up heap usage.
     *
     * @return This {@link QueryManager} instance
     * @see <a href="https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#cache_level2">L2 Cache docs</a>
     */
    public QueryManager withL2CacheDisabled() {
        disableL2Cache();
        return this;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //// BEGIN WRAPPER METHODS                                                                                      ////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    public PaginatedResult getProjects(final boolean includeMetrics, final boolean excludeInactive, final boolean onlyRoot) {
        return getProjectQueryManager().getProjects(includeMetrics, excludeInactive, onlyRoot);
    }

    public PaginatedResult getProjects(final boolean includeMetrics) {
        return getProjectQueryManager().getProjects(includeMetrics);
    }

    public PaginatedResult getProjects() {
        return getProjectQueryManager().getProjects();
    }

    public List<Project> getAllProjects() {
        return getProjectQueryManager().getAllProjects();
    }

    public List<Project> getAllProjects(boolean excludeInactive) {
        return getProjectQueryManager().getAllProjects(excludeInactive);
    }

    public PaginatedResult getProjects(final String name, final boolean excludeInactive, final boolean onlyRoot) {
        return getProjectQueryManager().getProjects(name, excludeInactive, onlyRoot);
    }

    public Project getProject(final String name, final String version) {
        return getProjectQueryManager().getProject(name, version);
    }

    public PaginatedResult getProjects(final Team team, final boolean excludeInactive, final boolean bypass, final boolean onlyRoot) {
        return getProjectQueryManager().getProjects(team, excludeInactive, bypass, onlyRoot);
    }

    public PaginatedResult getProjectsWithoutDescendantsOf(final boolean excludeInactive, final Project project) {
        return getProjectQueryManager().getProjectsWithoutDescendantsOf(excludeInactive, project);
    }

    public PaginatedResult getProjectsWithoutDescendantsOf(final String name, final boolean excludeInactive, final Project project) {
        return getProjectQueryManager().getProjectsWithoutDescendantsOf(name, excludeInactive, project);
    }

    public List<UUID> getParents(final Project project) {
        return getProjectQueryManager().getParents(project);
    }

    public boolean hasAccess(final Principal principal, final Project project) {
        return getProjectQueryManager().hasAccess(principal, project);
    }

    public PaginatedResult getProjects(final Tag tag, final boolean includeMetrics, final boolean excludeInactive, final boolean onlyRoot) {
        return getProjectQueryManager().getProjects(tag, includeMetrics, excludeInactive, onlyRoot);
    }

    public PaginatedResult getProjects(final Classifier classifier, final boolean includeMetrics, final boolean excludeInactive, final boolean onlyRoot) {
        return getProjectQueryManager().getProjects(classifier, includeMetrics, excludeInactive, onlyRoot);
    }

    public PaginatedResult getChildrenProjects(final UUID uuid, final boolean includeMetrics, final boolean excludeInactive) {
        return getProjectQueryManager().getChildrenProjects(uuid, includeMetrics, excludeInactive);
    }

    public PaginatedResult getChildrenProjects(final Tag tag, final UUID uuid, final boolean includeMetrics, final boolean excludeInactive) {
        return getProjectQueryManager().getChildrenProjects(tag, uuid, includeMetrics, excludeInactive);
    }

    public PaginatedResult getChildrenProjects(final Classifier classifier, final UUID uuid, final boolean includeMetrics, final boolean excludeInactive) {
        return getProjectQueryManager().getChildrenProjects(classifier, uuid, includeMetrics, excludeInactive);
    }

    public PaginatedResult getProjects(final Tag tag) {
        return getProjectQueryManager().getProjects(tag);
    }

    public Tag getTagByName(final String name) {
        return getProjectQueryManager().getTagByName(name);
    }

    public Tag createTag(final String name) {
        return getProjectQueryManager().createTag(name);
    }

    public Project createProject(String name, String description, String version, List<Tag> tags, Project parent, PackageURL purl, boolean active, boolean commitIndex) {
        return getProjectQueryManager().createProject(name, description, version, tags, parent, purl, active, commitIndex);
    }

    public Project createProject(final Project project, List<Tag> tags, boolean commitIndex) {
        return getProjectQueryManager().createProject(project, tags, commitIndex);
    }

    public Project updateProject(UUID uuid, String name, String description, String version, List<Tag> tags, PackageURL purl, boolean active, boolean commitIndex) {
        return getProjectQueryManager().updateProject(uuid, name, description, version, tags, purl, active, commitIndex);
    }

    public Project updateProject(Project transientProject, boolean commitIndex) {
        return getProjectQueryManager().updateProject(transientProject, commitIndex);
    }

    public boolean updateNewProjectACL(Project transientProject, Principal principal) {
        return getProjectQueryManager().updateNewProjectACL(transientProject, principal);
    }

    public Project clone(UUID from, String newVersion, boolean includeTags, boolean includeProperties,
                         boolean includeComponents, boolean includeServices, boolean includeAuditHistory,
                         boolean includeACL) {
        return getProjectQueryManager().clone(from, newVersion, includeTags, includeProperties,
                includeComponents, includeServices, includeAuditHistory, includeACL);
    }

    public Project updateLastBomImport(Project p, Date date, String bomFormat) {
        return getProjectQueryManager().updateLastBomImport(p, date, bomFormat);
    }

    public void recursivelyDelete(final Project project, final boolean commitIndex) {
        getProjectQueryManager().recursivelyDelete(project, commitIndex);
    }

    public ProjectProperty createProjectProperty(final Project project, final String groupName, final String propertyName,
                                                 final String propertyValue, final ProjectProperty.PropertyType propertyType,
                                                 final String description) {
        return getProjectQueryManager().createProjectProperty(project, groupName, propertyName, propertyValue, propertyType, description);
    }

    public ProjectProperty getProjectProperty(final Project project, final String groupName, final String propertyName) {
        return getProjectQueryManager().getProjectProperty(project, groupName, propertyName);
    }

    public List<ProjectProperty> getProjectProperties(final Project project) {
        return getProjectQueryManager().getProjectProperties(project);
    }

    public Bom createBom(Project project, Date imported, Bom.Format format, String specVersion, Integer bomVersion, String serialNumber, final UUID uploadToken) {
        return getBomQueryManager().createBom(project, imported, format, specVersion, bomVersion, serialNumber, uploadToken);
    }

    public List<Bom> getAllBoms(Project project) {
        return getBomQueryManager().getAllBoms(project);
    }

    public void deleteBoms(Project project) {
        getBomQueryManager().deleteBoms(project);
    }

    public Vex createVex(Project project, Date imported, Vex.Format format, String specVersion, Integer vexVersion, String serialNumber) {
        return getVexQueryManager().createVex(project, imported, format, specVersion, vexVersion, serialNumber);
    }

    public List<Vex> getAllVexs(Project project) {
        return getVexQueryManager().getAllVexs(project);
    }

    public void deleteVexs(Project project) {
        getVexQueryManager().deleteVexs(project);
    }

    public PaginatedResult getComponents(final boolean includeMetrics) {
        return getComponentQueryManager().getComponents(includeMetrics);
    }

    public PaginatedResult getComponents() {
        return getComponentQueryManager().getComponents(false);
    }

    public List<Component> getAllComponents() {
        return getComponentQueryManager().getAllComponents();
    }

    public PaginatedResult getComponentByHash(String hash) {
        return getComponentQueryManager().getComponentByHash(hash);
    }

    public PaginatedResult getComponents(ComponentIdentity identity) {
        return getComponentQueryManager().getComponents(identity);
    }

    public PaginatedResult getComponents(ComponentIdentity identity, boolean includeMetrics) {
        return getComponentQueryManager().getComponents(identity, includeMetrics);
    }

    public PaginatedResult getComponents(ComponentIdentity identity, Project project, boolean includeMetrics) {
        return getComponentQueryManager().getComponents(identity, project, includeMetrics);
    }

    public Component createComponent(Component component, boolean commitIndex) {
        return getComponentQueryManager().createComponent(component, commitIndex);
    }

    public Component cloneComponent(Component sourceComponent, Project destinationProject, boolean commitIndex) {
        return getComponentQueryManager().cloneComponent(sourceComponent, destinationProject, commitIndex);
    }

    public Component updateComponent(Component transientComponent, boolean commitIndex) {
        return getComponentQueryManager().updateComponent(transientComponent, commitIndex);
    }

    void deleteComponents(Project project) {
        getComponentQueryManager().deleteComponents(project);
    }

    public void recursivelyDelete(Component component, boolean commitIndex) {
        getComponentQueryManager().recursivelyDelete(component, commitIndex);
    }

    public Map<String, Component> getDependencyGraphForComponent(Project project, Component component) {
        return getComponentQueryManager().getDependencyGraphForComponent(project, component);
    }

    public PaginatedResult getLicenses() {
        return getLicenseQueryManager().getLicenses();
    }

    public List<License> getAllLicensesConcise() {
        return getLicenseQueryManager().getAllLicensesConcise();
    }

    public License getLicense(String licenseId) {
        return getLicenseQueryManager().getLicense(licenseId);
    }

    License synchronizeLicense(License license, boolean commitIndex) {
        return getLicenseQueryManager().synchronizeLicense(license, commitIndex);
    }


    public License createCustomLicense(License license, boolean commitIndex) {
        return getLicenseQueryManager().createCustomLicense(license, commitIndex);
    }

    public void deleteLicense(final License license, final boolean commitIndex) {
        getLicenseQueryManager().deleteLicense(license, commitIndex);
    }

    public PaginatedResult getPolicies() {
        return getPolicyQueryManager().getPolicies();
    }

    public List<Policy> getAllPolicies() {
        return getPolicyQueryManager().getAllPolicies();
    }

    public List<Policy> getApplicablePolicies(final Project project) {
        return getPolicyQueryManager().getApplicablePolicies(project);
    }

    public Policy getPolicy(final String name) {
        return getPolicyQueryManager().getPolicy(name);
    }

    public Policy createPolicy(String name, Policy.Operator operator, Policy.ViolationState violationState) {
        return getPolicyQueryManager().createPolicy(name, operator, violationState);
    }

    public void removeProjectFromPolicies(final Project project) {
        getPolicyQueryManager().removeProjectFromPolicies(project);
    }

    public PolicyCondition createPolicyCondition(final Policy policy, final PolicyCondition.Subject subject,
                                                 final PolicyCondition.Operator operator, final String value) {
        return getPolicyQueryManager().createPolicyCondition(policy, subject, operator, value);
    }

    public PolicyCondition updatePolicyCondition(final PolicyCondition policyCondition) {
        return getPolicyQueryManager().updatePolicyCondition(policyCondition);
    }

    public synchronized void reconcilePolicyViolations(final Component component, final List<PolicyViolation> policyViolations) {
        getPolicyQueryManager().reconcilePolicyViolations(component, policyViolations);
    }

    public synchronized PolicyViolation addPolicyViolationIfNotExist(final PolicyViolation pv) {
        return getPolicyQueryManager().addPolicyViolationIfNotExist(pv);
    }

    public List<PolicyViolation> getAllPolicyViolations() {
        return getPolicyQueryManager().getAllPolicyViolations();
    }

    public List<PolicyViolation> getAllPolicyViolations(final PolicyCondition policyCondition) {
        return getPolicyQueryManager().getAllPolicyViolations(policyCondition);
    }

    public List<PolicyViolation> getAllPolicyViolations(final Component component) {
        return getPolicyQueryManager().getAllPolicyViolations(component);
    }

    public List<PolicyViolation> getAllPolicyViolations(final Component component, final boolean includeSuppressed) {
        return getPolicyQueryManager().getAllPolicyViolations(component, includeSuppressed);
    }

    public List<PolicyViolation> getAllPolicyViolations(final Project project) {
        return getPolicyQueryManager().getAllPolicyViolations(project);
    }

    public PaginatedResult getPolicyViolations(final Project project, boolean includeSuppressed) {
        return getPolicyQueryManager().getPolicyViolations(project, includeSuppressed);
    }

    public PaginatedResult getPolicyViolations(final Component component, boolean includeSuppressed) {
        return getPolicyQueryManager().getPolicyViolations(component, includeSuppressed);
    }

    public PaginatedResult getPolicyViolations(boolean includeSuppressed) {
        return getPolicyQueryManager().getPolicyViolations(includeSuppressed);
    }

    public ViolationAnalysis getViolationAnalysis(Component component, PolicyViolation policyViolation) {
        return getPolicyQueryManager().getViolationAnalysis(component, policyViolation);
    }

    public ViolationAnalysis makeViolationAnalysis(Component component, PolicyViolation policyViolation,
                                                   ViolationAnalysisState violationAnalysisState, Boolean isSuppressed) {
        return getPolicyQueryManager().makeViolationAnalysis(component, policyViolation, violationAnalysisState, isSuppressed);
    }

    public ViolationAnalysisComment makeViolationAnalysisComment(ViolationAnalysis violationAnalysis, String comment, String commenter) {
        return getPolicyQueryManager().makeViolationAnalysisComment(violationAnalysis, comment, commenter);
    }

    void deleteViolationAnalysisTrail(Component component) {
        getPolicyQueryManager().deleteViolationAnalysisTrail(component);
    }

    void deleteViolationAnalysisTrail(Project project) {
        getPolicyQueryManager().deleteViolationAnalysisTrail(project);
    }

    public PaginatedResult getLicenseGroups() {
        return getPolicyQueryManager().getLicenseGroups();
    }

    public LicenseGroup getLicenseGroup(final String name) {
        return getPolicyQueryManager().getLicenseGroup(name);
    }

    public LicenseGroup createLicenseGroup(String name) {
        return getPolicyQueryManager().createLicenseGroup(name);
    }

    public boolean doesLicenseGroupContainLicense(final LicenseGroup lg, final License license) {
        return getPolicyQueryManager().doesLicenseGroupContainLicense(lg, license);
    }

    public void deletePolicy(final Policy policy) {
        getPolicyQueryManager().deletePolicy(policy);
    }

    void deletePolicyViolations(Component component) {
        getPolicyQueryManager().deletePolicyViolations(component);
    }

    public void deletePolicyViolations(Project project) {
        getPolicyQueryManager().deletePolicyViolations(project);
    }

    public void deletePolicyViolationsOfComponent(final Component component) {
        getPolicyQueryManager().deletePolicyViolationsOfComponent(component);
    }

    public long getAuditedCount(final Component component, final PolicyViolation.Type type) {
        return getPolicyQueryManager().getAuditedCount(component, type);
    }

    public void deletePolicyCondition(PolicyCondition policyCondition) {
        getPolicyQueryManager().deletePolicyCondition(policyCondition);
    }

    public Vulnerability createVulnerability(Vulnerability vulnerability, boolean commitIndex) {
        return getVulnerabilityQueryManager().createVulnerability(vulnerability, commitIndex);
    }

    public Vulnerability updateVulnerability(Vulnerability transientVulnerability, boolean commitIndex) {
        return getVulnerabilityQueryManager().updateVulnerability(transientVulnerability, commitIndex);
    }

    public Vulnerability synchronizeVulnerability(Vulnerability vulnerability, boolean commitIndex) {
        return getVulnerabilityQueryManager().synchronizeVulnerability(vulnerability, commitIndex);
    }

    public Vulnerability getVulnerabilityByVulnId(String source, String vulnId) {
        return getVulnerabilityQueryManager().getVulnerabilityByVulnId(source, vulnId, false);
    }

    public Vulnerability getVulnerabilityByVulnId(String source, String vulnId, boolean includeVulnerableSoftware) {
        return getVulnerabilityQueryManager().getVulnerabilityByVulnId(source, vulnId, includeVulnerableSoftware);
    }

    public Vulnerability getVulnerabilityByVulnId(Vulnerability.Source source, String vulnId) {
        return getVulnerabilityQueryManager().getVulnerabilityByVulnId(source, vulnId, false);
    }

    public Vulnerability getVulnerabilityByVulnId(Vulnerability.Source source, String vulnId, boolean includeVulnerableSoftware) {
        return getVulnerabilityQueryManager().getVulnerabilityByVulnId(source, vulnId, includeVulnerableSoftware);
    }

    public List<Vulnerability> getVulnerabilitiesForNpmModule(String module) {
        return getVulnerabilityQueryManager().getVulnerabilitiesForNpmModule(module);
    }

    public void addVulnerability(Vulnerability vulnerability, Component component, AnalyzerIdentity analyzerIdentity) {
        getVulnerabilityQueryManager().addVulnerability(vulnerability, component, analyzerIdentity);
    }

    public void addVulnerability(Vulnerability vulnerability, Component component, AnalyzerIdentity analyzerIdentity,
                                 String alternateIdentifier, String referenceUrl) {
        getVulnerabilityQueryManager().addVulnerability(vulnerability, component, analyzerIdentity, alternateIdentifier, referenceUrl);
    }

    public void removeVulnerability(Vulnerability vulnerability, Component component) {
        getVulnerabilityQueryManager().removeVulnerability(vulnerability, component);
    }

    public FindingAttribution getFindingAttribution(Vulnerability vulnerability, Component component) {
        return getVulnerabilityQueryManager().getFindingAttribution(vulnerability, component);
    }

    void deleteFindingAttributions(Component component) {
        getVulnerabilityQueryManager().deleteFindingAttributions(component);
    }

    void deleteFindingAttributions(Project project) {
        getVulnerabilityQueryManager().deleteFindingAttributions(project);
    }

    public List<VulnerableSoftware> reconcileVulnerableSoftware(final Vulnerability vulnerability,
                                                                final List<VulnerableSoftware> vsListOld,
                                                                final List<VulnerableSoftware> vsList,
                                                                final Vulnerability.Source source) {
        return getVulnerabilityQueryManager().reconcileVulnerableSoftware(vulnerability, vsListOld, vsList, source);
    }

    public List<AffectedVersionAttribution> getAffectedVersionAttributions(Vulnerability vulnerability, VulnerableSoftware vulnerableSoftware) {
        return getVulnerabilityQueryManager().getAffectedVersionAttributions(vulnerability, vulnerableSoftware);
    }

    public AffectedVersionAttribution getAffectedVersionAttribution(Vulnerability vulnerability, VulnerableSoftware vulnerableSoftware, Vulnerability.Source source) {
        return getVulnerabilityQueryManager().getAffectedVersionAttribution(vulnerability, vulnerableSoftware, source);
    }

    public void updateAffectedVersionAttributions(final Vulnerability vulnerability,
                                                  final List<VulnerableSoftware> vsList,
                                                  final Vulnerability.Source source) {
        getVulnerabilityQueryManager().updateAffectedVersionAttributions(vulnerability, vsList, source);
    }

    public void updateAffectedVersionAttribution(final Vulnerability vulnerability,
                                                 final VulnerableSoftware vulnerableSoftware,
                                                 final Vulnerability.Source source) {
        getVulnerabilityQueryManager().updateAffectedVersionAttribution(vulnerability, vulnerableSoftware, source);
    }

    public void deleteAffectedVersionAttribution(final Vulnerability vulnerability,
                                                 final VulnerableSoftware vulnerableSoftware,
                                                 final Vulnerability.Source source) {
        getVulnerabilityQueryManager().deleteAffectedVersionAttribution(vulnerability, vulnerableSoftware, source);
    }

    public void deleteAffectedVersionAttributions(final Vulnerability vulnerability) {
        getVulnerabilityQueryManager().deleteAffectedVersionAttributions(vulnerability);
    }

    public boolean contains(Vulnerability vulnerability, Component component) {
        return getVulnerabilityQueryManager().contains(vulnerability, component);
    }

    public Cpe synchronizeCpe(Cpe cpe, boolean commitIndex) {
        return getVulnerableSoftwareQueryManager().synchronizeCpe(cpe, commitIndex);
    }

    public Cpe getCpeBy23(String cpe23) {
        return getVulnerableSoftwareQueryManager().getCpeBy23(cpe23);
    }

    public PaginatedResult getCpes() {
        return getVulnerableSoftwareQueryManager().getCpes();
    }

    public List<Cpe> getCpes(final String cpeString) {
        return getVulnerableSoftwareQueryManager().getCpes(cpeString);
    }

    public List<Cpe> getCpes(final String part, final String vendor, final String product, final String version) {
        return getVulnerableSoftwareQueryManager().getCpes(part, vendor, product, version);
    }

    public VulnerableSoftware getVulnerableSoftwareByCpe23(String cpe23,
                                                           String versionEndExcluding, String versionEndIncluding,
                                                           String versionStartExcluding, String versionStartIncluding) {
        return getVulnerableSoftwareQueryManager().getVulnerableSoftwareByCpe23(cpe23, versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding);
    }

    public VulnerableSoftware getVulnerableSoftwareByCpe23AndVersion(String cpe23, String version) {
        return getVulnerableSoftwareQueryManager().getVulnerableSoftwareByCpe23AndVersion(cpe23, version);
    }

    public PaginatedResult getVulnerableSoftware() {
        return getVulnerableSoftwareQueryManager().getVulnerableSoftware();
    }

    public List<VulnerableSoftware> getAllVulnerableSoftwareByCpe(final String cpeString) {
        return getVulnerableSoftwareQueryManager().getAllVulnerableSoftwareByCpe(cpeString);
    }

    public VulnerableSoftware getVulnerableSoftwareByPurl(String purlType, String purlNamespace, String purlName,
                                                          String versionEndExcluding, String versionEndIncluding,
                                                          String versionStartExcluding, String versionStartIncluding) {
        return getVulnerableSoftwareQueryManager().getVulnerableSoftwareByPurl(purlType, purlNamespace, purlName, versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding);
    }

    public List<VulnerableSoftware> getVulnerableSoftwareByVulnId(final String source, final String vulnId) {
        return getVulnerableSoftwareQueryManager().getVulnerableSoftwareByVulnId(source, vulnId);
    }

    public List<VulnerableSoftware> getAllVulnerableSoftwareByPurl(final PackageURL purl) {
        return getVulnerableSoftwareQueryManager().getAllVulnerableSoftwareByPurl(purl);
    }

    public List<VulnerableSoftware> getAllVulnerableSoftware(final String cpePart, final String cpeVendor, final String cpeProduct, final String cpeVersion, final PackageURL purl) {
        return getVulnerableSoftwareQueryManager().getAllVulnerableSoftware(cpePart, cpeVendor, cpeProduct, cpeVersion, purl);
    }

    public List<VulnerableSoftware> getAllVulnerableSoftware(final String cpePart, final String cpeVendor, final String cpeProduct, final PackageURL purl) {
        return getVulnerableSoftwareQueryManager().getAllVulnerableSoftware(cpePart, cpeVendor, cpeProduct, purl);
    }

    public Cwe createCweIfNotExist(int id, String name) {
        return getVulnerableSoftwareQueryManager().createCweIfNotExist(id, name);
    }

    public Cwe getCweById(int cweId) {
        return getVulnerableSoftwareQueryManager().getCweById(cweId);
    }

    public PaginatedResult getCwes() {
        return getVulnerableSoftwareQueryManager().getCwes();
    }

    public List<Cwe> getAllCwes() {
        return getVulnerableSoftwareQueryManager().getAllCwes();
    }

    public Component matchSingleIdentity(final Project project, final ComponentIdentity cid) {
        return getComponentQueryManager().matchSingleIdentity(project, cid);
    }

    public List<Component> matchIdentity(final Project project, final ComponentIdentity cid) {
        return getComponentQueryManager().matchIdentity(project, cid);
    }

    public List<Component> matchIdentity(final ComponentIdentity cid) {
        return getComponentQueryManager().matchIdentity(cid);
    }

    public void reconcileComponents(Project project, List<Component> existingProjectComponents, List<Component> components) {
        getComponentQueryManager().reconcileComponents(project, existingProjectComponents, components);
    }

    public List<Component> getAllComponents(Project project) {
        return getComponentQueryManager().getAllComponents(project);
    }

    public PaginatedResult getComponents(final Project project, final boolean includeMetrics) {
        return getComponentQueryManager().getComponents(project, includeMetrics);
    }

    public ServiceComponent matchServiceIdentity(final Project project, final ComponentIdentity cid) {
        return getServiceComponentQueryManager().matchServiceIdentity(project, cid);
    }

    public void reconcileServiceComponents(Project project, List<ServiceComponent> existingProjectServices, List<ServiceComponent> services) {
        getServiceComponentQueryManager().reconcileServiceComponents(project, existingProjectServices, services);
    }

    public ServiceComponent createServiceComponent(ServiceComponent service, boolean commitIndex) {
        return getServiceComponentQueryManager().createServiceComponent(service, commitIndex);
    }

    public List<ServiceComponent> getAllServiceComponents() {
        return getServiceComponentQueryManager().getAllServiceComponents();
    }

    public List<ServiceComponent> getAllServiceComponents(Project project) {
        return getServiceComponentQueryManager().getAllServiceComponents(project);
    }

    public PaginatedResult getServiceComponents() {
        return getServiceComponentQueryManager().getServiceComponents();
    }

    public PaginatedResult getServiceComponents(final boolean includeMetrics) {
        return getServiceComponentQueryManager().getServiceComponents(includeMetrics);
    }

    public PaginatedResult getServiceComponents(final Project project, final boolean includeMetrics) {
        return getServiceComponentQueryManager().getServiceComponents(project, includeMetrics);
    }

    public ServiceComponent cloneServiceComponent(ServiceComponent sourceService, Project destinationProject, boolean commitIndex) {
        return getServiceComponentQueryManager().cloneServiceComponent(sourceService, destinationProject, commitIndex);
    }

    public ServiceComponent updateServiceComponent(ServiceComponent transientServiceComponent, boolean commitIndex) {
        return getServiceComponentQueryManager().updateServiceComponent(transientServiceComponent, commitIndex);
    }

    public void deleteServiceComponents(final Project project) {
        getServiceComponentQueryManager().deleteServiceComponents(project);
    }

    public void recursivelyDelete(ServiceComponent service, boolean commitIndex) {
        getServiceComponentQueryManager().recursivelyDelete(service, commitIndex);
    }

    public PaginatedResult getVulnerabilities() {
        return getVulnerabilityQueryManager().getVulnerabilities();
    }

    public PaginatedResult getVulnerabilities(Component component) {
        return getVulnerabilityQueryManager().getVulnerabilities(component);
    }

    public PaginatedResult getVulnerabilities(Component component, boolean includeSuppressed) {
        return getVulnerabilityQueryManager().getVulnerabilities(component, includeSuppressed);
    }

    public List<Component> getAllVulnerableComponents(Project project, Vulnerability vulnerability, boolean includeSuppressed) {
        return getVulnerabilityQueryManager().getAllVulnerableComponents(project, vulnerability, includeSuppressed);
    }

    public List<Vulnerability> getAllVulnerabilities(Component component) {
        return getVulnerabilityQueryManager().getAllVulnerabilities(component);
    }

    public List<Vulnerability> getAllVulnerabilities(Component component, boolean includeSuppressed) {
        return getVulnerabilityQueryManager().getAllVulnerabilities(component, includeSuppressed);
    }

    public long getVulnerabilityCount(Project project, boolean includeSuppressed) {
        return getVulnerabilityQueryManager().getVulnerabilityCount(project, includeSuppressed);
    }

    public List<Vulnerability> getVulnerabilities(Project project, boolean includeSuppressed) {
        return getVulnerabilityQueryManager().getVulnerabilities(project, includeSuppressed);
    }

    public long getAuditedCount() {
        return getFindingsQueryManager().getAuditedCount();
    }

    public long getAuditedCount(Project project) {
        return getFindingsQueryManager().getAuditedCount(project);
    }

    public long getAuditedCount(Component component) {
        return getFindingsQueryManager().getAuditedCount(component);
    }

    public long getAuditedCount(Project project, Component component) {
        return getFindingsQueryManager().getAuditedCount(project, component);
    }

    public long getSuppressedCount() {
        return getFindingsQueryManager().getSuppressedCount();
    }

    public long getSuppressedCount(Project project) {
        return getFindingsQueryManager().getSuppressedCount(project);
    }

    public long getSuppressedCount(Component component) {
        return getFindingsQueryManager().getSuppressedCount(component);
    }

    public long getSuppressedCount(Project project, Component component) {
        return getFindingsQueryManager().getSuppressedCount(project, component);
    }

    public List<Project> getProjects(final Vulnerability vulnerability, final Set<String> fetchGroups) {
        return getVulnerabilityQueryManager().getProjects(vulnerability, fetchGroups);
    }

    public VulnerabilityAlias synchronizeVulnerabilityAlias(VulnerabilityAlias alias) {
        return getVulnerabilityQueryManager().synchronizeVulnerabilityAlias(alias);
    }

    public List<VulnerabilityAlias> getVulnerabilityAliases(Vulnerability vulnerability) {
        return getVulnerabilityQueryManager().getVulnerabilityAliases(vulnerability);
    }

    List<Analysis> getAnalyses(Project project) {
        return getFindingsQueryManager().getAnalyses(project);
    }

    public Analysis getAnalysis(Component component, Vulnerability vulnerability) {
        return getFindingsQueryManager().getAnalysis(component, vulnerability);
    }

    public Analysis makeAnalysis(Component component, Vulnerability vulnerability, AnalysisState analysisState,
                                 AnalysisJustification analysisJustification, AnalysisResponse analysisResponse,
                                 String analysisDetails, Boolean isSuppressed) {
        return getFindingsQueryManager().makeAnalysis(component, vulnerability, analysisState, analysisJustification, analysisResponse, analysisDetails, isSuppressed);
    }

    public AnalysisComment makeAnalysisComment(Analysis analysis, String comment, String commenter) {
        return getFindingsQueryManager().makeAnalysisComment(analysis, comment, commenter);
    }

    void deleteAnalysisTrail(Component component) {
        getFindingsQueryManager().deleteAnalysisTrail(component);
    }

    void deleteAnalysisTrail(Project project) {
        getFindingsQueryManager().deleteAnalysisTrail(project);
    }

    public List<Finding> getFindings(Project project) {
        return getFindingsQueryManager().getFindings(project);
    }

    public List<Finding> getFindings(Project project, boolean includeSuppressed) {
        return getFindingsQueryManager().getFindings(project, includeSuppressed);
    }

    public List<VulnerabilityMetrics> getVulnerabilityMetrics() {
        return getMetricsQueryManager().getVulnerabilityMetrics();
    }

    public PortfolioMetrics getMostRecentPortfolioMetrics() {
        return getMetricsQueryManager().getMostRecentPortfolioMetrics();
    }

    public PaginatedResult getPortfolioMetrics() {
        return getMetricsQueryManager().getPortfolioMetrics();
    }

    public List<PortfolioMetrics> getPortfolioMetricsSince(Date since) {
        return getMetricsQueryManager().getPortfolioMetricsSince(since);
    }

    public ProjectMetrics getMostRecentProjectMetrics(Project project) {
        return getMetricsQueryManager().getMostRecentProjectMetrics(project);
    }

    public PaginatedResult getProjectMetrics(Project project) {
        return getMetricsQueryManager().getProjectMetrics(project);
    }

    public List<ProjectMetrics> getProjectMetricsSince(Project project, Date since) {
        return getMetricsQueryManager().getProjectMetricsSince(project, since);
    }

    public DependencyMetrics getMostRecentDependencyMetrics(Component component) {
        return getMetricsQueryManager().getMostRecentDependencyMetrics(component);
    }

    public PaginatedResult getDependencyMetrics(Component component) {
        return getMetricsQueryManager().getDependencyMetrics(component);
    }

    public List<DependencyMetrics> getDependencyMetricsSince(Component component, Date since) {
        return getMetricsQueryManager().getDependencyMetricsSince(component, since);
    }

    public void synchronizeVulnerabilityMetrics(List<VulnerabilityMetrics> metrics) {
        getMetricsQueryManager().synchronizeVulnerabilityMetrics(metrics);
    }

    void deleteMetrics(Project project) {
        getMetricsQueryManager().deleteMetrics(project);
    }

    void deleteMetrics(Component component) {
        getMetricsQueryManager().deleteMetrics(component);
    }

    public PaginatedResult getRepositories() {
        return getRepositoryQueryManager().getRepositories();
    }

    public List<Repository> getAllRepositories() {
        return getRepositoryQueryManager().getAllRepositories();
    }

    public PaginatedResult getRepositories(RepositoryType type) {
        return getRepositoryQueryManager().getRepositories(type);
    }

    public List<Repository> getAllRepositoriesOrdered(RepositoryType type) {
        return getRepositoryQueryManager().getAllRepositoriesOrdered(type);
    }

    public boolean repositoryExist(RepositoryType type, String identifier) {
        return getRepositoryQueryManager().repositoryExist(type, identifier);
    }

    public Repository createRepository(RepositoryType type, String identifier, String url, boolean enabled, boolean internal, boolean isAuthenticationRequired, String username, String password) {
        return getRepositoryQueryManager().createRepository(type, identifier, url, enabled, internal, isAuthenticationRequired, username, password);
    }

    public Repository updateRepository(UUID uuid, String identifier, String url, boolean internal, boolean authenticationRequired, String username, String password, boolean enabled) {
        return getRepositoryQueryManager().updateRepository(uuid, identifier, url, internal, authenticationRequired, username, password, enabled);
    }

    public RepositoryMetaComponent getRepositoryMetaComponent(RepositoryType repositoryType, String namespace, String name) {
        return getRepositoryQueryManager().getRepositoryMetaComponent(repositoryType, namespace, name);
    }

    public synchronized RepositoryMetaComponent synchronizeRepositoryMetaComponent(final RepositoryMetaComponent transientRepositoryMetaComponent) {
        return getRepositoryQueryManager().synchronizeRepositoryMetaComponent(transientRepositoryMetaComponent);
    }

    public NotificationRule createNotificationRule(String name, NotificationScope scope, NotificationLevel level, NotificationPublisher publisher) {
        return getNotificationQueryManager().createNotificationRule(name, scope, level, publisher);
    }

    public NotificationRule updateNotificationRule(NotificationRule transientRule) {
        return getNotificationQueryManager().updateNotificationRule(transientRule);
    }

    public PaginatedResult getNotificationRules() {
        return getNotificationQueryManager().getNotificationRules();
    }

    public List<NotificationPublisher> getAllNotificationPublishers() {
        return getNotificationQueryManager().getAllNotificationPublishers();
    }

    public NotificationPublisher getNotificationPublisher(final String name) {
        return getNotificationQueryManager().getNotificationPublisher(name);
    }

    public NotificationPublisher getDefaultNotificationPublisher(final PublisherClass clazz) {
        return getNotificationQueryManager().getDefaultNotificationPublisher(clazz);
    }

    public NotificationPublisher getDefaultNotificationPublisherByName(String publisherName) {
        return getNotificationQueryManager().getDefaultNotificationPublisherByName(publisherName);
    }

    public NotificationPublisher createNotificationPublisher(final String name, final String description,
                                                             final String publisherClass, final String templateContent,
                                                             final String templateMimeType, final boolean defaultPublisher) {
        return getNotificationQueryManager().createNotificationPublisher(name, description, publisherClass, templateContent, templateMimeType, defaultPublisher);
    }

    public NotificationPublisher updateNotificationPublisher(NotificationPublisher transientPublisher) {
        return getNotificationQueryManager().updateNotificationPublisher(transientPublisher);
    }

    public void deleteNotificationPublisher(NotificationPublisher notificationPublisher) {
        getNotificationQueryManager().deleteNotificationPublisher(notificationPublisher);
    }

    public void removeProjectFromNotificationRules(final Project project) {
        getNotificationQueryManager().removeProjectFromNotificationRules(project);
    }

    public void removeTeamFromNotificationRules(final Team team) {
        getNotificationQueryManager().removeTeamFromNotificationRules(team);
    }

    /**
     * Determines if a config property is enabled or not.
     *
     * @param configPropertyConstants the property to query
     * @return true if enabled, false if not
     */
    public boolean isEnabled(final ConfigPropertyConstants configPropertyConstants) {
        final ConfigProperty property = getConfigProperty(
                configPropertyConstants.getGroupName(), configPropertyConstants.getPropertyName()
        );
        if (property != null && ConfigProperty.PropertyType.BOOLEAN == property.getPropertyType()) {
            return BooleanUtil.valueOf(property.getPropertyValue());
        }
        return false;
    }

    public void bind(Project project, List<Tag> tags) {
        getProjectQueryManager().bind(project, tags);
    }

    public boolean hasAccessManagementPermission(final Object principal) {
        if (principal instanceof final UserPrincipal userPrincipal) {
            return hasAccessManagementPermission(userPrincipal);
        } else if (principal instanceof final ApiKey apiKey) {
            return hasAccessManagementPermission(apiKey);
        }

        throw new IllegalArgumentException("Provided principal is of invalid type " + ClassUtils.getName(principal));
    }

    public boolean hasAccessManagementPermission(final UserPrincipal userPrincipal) {
        return getProjectQueryManager().hasAccessManagementPermission(userPrincipal);
    }

    public boolean hasAccessManagementPermission(final ApiKey apiKey) {
        return getProjectQueryManager().hasAccessManagementPermission(apiKey);
    }

    public PaginatedResult getTags(String policyUuid) {
        return getTagQueryManager().getTags(policyUuid);
    }

    /**
     * Fetch multiple objects from the data store by their ID.
     *
     * @param clazz       {@link Class} of the objects to fetch
     * @param ids         IDs of the objects to fetch
     * @param fetchGroups The fetch groups to use
     * @param <T>         Type of the objects to fetch
     * @return The fetched objects
     * @since 5.0.0
     */
    public <T> List<T> getObjectsById(final Class<T> clazz, final Collection<Long> ids, final Collection<String> fetchGroups) {
        final Query<T> query = pm.newQuery(clazz);
        try {
            if (fetchGroups != null && !fetchGroups.isEmpty()) {
                query.getFetchPlan().setGroups(fetchGroups);
            }
            query.setFilter(":ids.contains(this.id)");
            query.setNamedParameters(Map.of("ids", ids));
            return List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }
    }

    /**
     * Detach a persistent object using the provided fetch groups.
     * <p>
     * {@code fetchGroups} will override any other fetch groups set on the {@link PersistenceManager},
     * even the default one. If inclusion of the default fetch group is desired, it must be
     * included in {@code fetchGroups} explicitly.
     * <p>
     * Eventually, this may be moved to {@link alpine.persistence.AbstractAlpineQueryManager}.
     *
     * @param object      The persistent object to detach
     * @param fetchGroups Fetch groups to use for this operation
     * @param <T>         Type of the object
     * @return The detached object
     * @since 4.8.0
     */
    public <T> T detachWithGroups(final T object, final List<String> fetchGroups) {
        final int origDetachOptions = pm.getFetchPlan().getDetachmentOptions();
        final Set<?> origFetchGroups = pm.getFetchPlan().getGroups();
        try {
            pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
            pm.getFetchPlan().setGroups(fetchGroups);
            return pm.detachCopy(object);
        } finally {
            // Restore previous settings to not impact other operations performed
            // by this persistence manager.
            pm.getFetchPlan().setDetachmentOptions(origDetachOptions);
            pm.getFetchPlan().setGroups(origFetchGroups);
        }
    }

    /**
     * Fetch an object from the datastore by its {@link UUID}, using the provided fetch groups.
     * <p>
     * {@code fetchGroups} will override any other fetch groups set on the {@link PersistenceManager},
     * even the default one. If inclusion of the default fetch group is desired, it must be
     * included in {@code fetchGroups} explicitly.
     * <p>
     * Eventually, this may be moved to {@link alpine.persistence.AbstractAlpineQueryManager}.
     *
     * @param clazz       Class of the object to fetch
     * @param uuid        {@link UUID} of the object to fetch
     * @param fetchGroups Fetch groups to use for this operation
     * @param <T>         Type of the object
     * @return The object if found, otherwise {@code null}
     * @since 4.6.0
     */
    public <T> T getObjectByUuid(final Class<T> clazz, final UUID uuid, final List<String> fetchGroups) {
        final Query<T> query = pm.newQuery(clazz);
        try {
            query.setFilter("uuid == :uuid");
            query.setParameters(uuid);
            query.getFetchPlan().setGroups(fetchGroups);
            return query.executeUnique();
        } finally {
            query.closeAll();
        }
    }

    /**
     * Convenience method to execute a given {@link Runnable} within the context of a {@link Transaction}.
     * <p>
     * Eventually, this may be moved to {@link alpine.persistence.AbstractAlpineQueryManager}.
     *
     * @param runnable The {@link Runnable} to execute
     * @since 4.6.0
     */
    public void runInTransaction(final Runnable runnable) {
        final Transaction trx = pm.currentTransaction();
        try {
            trx.begin();
            runnable.run();
            trx.commit();
        } finally {
            if (trx.isActive()) {
                trx.rollback();
            }
        }
    }

    /**
     * Convenience method to execute a given {@link Supplier} within the context of a {@link Transaction}.
     *
     * @param supplier The {@link Supplier} to execute
     * @param <T>      Type of the result of {@code supplier}
     * @return The result of the execution of {@code supplier}
     */
    public <T> T runInTransaction(final Supplier<T> supplier) {
        final Transaction trx = pm.currentTransaction();
        try {
            trx.begin();
            final T result = supplier.get();
            trx.commit();
            return result;
        } finally {
            if (trx.isActive()) {
                trx.rollback();
            }
        }
    }

    public <T> T runInRetryableTransaction(final Supplier<T> supplier, final Predicate<Throwable> retryOn) {
        final var retryConfig = RetryConfig.custom()
                .retryOnException(retryOn)
                .maxAttempts(3)
                .build();

        return Retry.of("runInRetryableTransaction", retryConfig)
                .executeSupplier(() -> runInTransaction(supplier));
    }

    public void recursivelyDeleteTeam(Team team) {
        pm.setProperty("datanucleus.query.sql.allowAll", true);
        final Transaction trx = pm.currentTransaction();
        pm.currentTransaction().begin();
        pm.deletePersistentAll(team.getApiKeys());
        String aclDeleteQuery = """
                    DELETE FROM PROJECT_ACCESS_TEAMS WHERE \"PROJECT_ACCESS_TEAMS\".\"TEAM_ID\" = ?      
                """;
        final Query query = pm.newQuery(JDOQuery.SQL_QUERY_LANGUAGE, aclDeleteQuery);
        query.executeWithArray(team.getId());
        pm.deletePersistent(team);
        pm.currentTransaction().commit();
    }

    /**
     * Create a new {@link VulnerabilityScan} record.
     * <p>
     * This method expects that access to the {@link VulnerabilityScan} table is serialized
     * through Kafka events, keyed by the scan's token. This assumption allows for optimistic
     * locking to be used.
     *
     * @param scanToken       The token that uniquely identifies the scan for clients
     * @param expectedResults Number of expected {@link ScanStatus #SCAN_STATUS_COMPLETE} events for this scan
     * @return The created {@link VulnerabilityScan}
     */
    public VulnerabilityScan createVulnerabilityScan(final VulnerabilityScan.TargetType targetType,
                                                     final UUID targetIdentifier, final String scanToken,
                                                     final int expectedResults) {
        final Transaction trx = pm.currentTransaction();
        trx.setOptimistic(true);
        try {
            trx.begin();
            final var scan = new VulnerabilityScan();
            scan.setToken(scanToken);
            scan.setTargetType(targetType);
            scan.setTargetIdentifier(targetIdentifier);
            scan.setStatus(VulnerabilityScan.Status.IN_PROGRESS);
            scan.setFailureThreshold(0.05);
            final var startDate = new Date();
            scan.setStartedAt(startDate);
            scan.setUpdatedAt(startDate);
            scan.setExpectedResults(expectedResults);
            pm.makePersistent(scan);
            trx.commit();
            return scan;
        } finally {
            if (trx.isActive()) {
                trx.rollback();
            }
        }
    }

    /**
     * Fetch a {@link VulnerabilityScan} by its token.
     *
     * @param token The token that uniquely identifies the scan for clients
     * @return A {@link VulnerabilityScan}, or {@code null} when no {@link VulnerabilityScan} was found
     */
    public VulnerabilityScan getVulnerabilityScan(final String token) {
        final Transaction trx = pm.currentTransaction();
        trx.setOptimistic(true);
        trx.setRollbackOnly(); // We won't commit anything
        try {
            trx.begin();
            final Query<VulnerabilityScan> scanQuery = pm.newQuery(VulnerabilityScan.class);
            scanQuery.setFilter("token == :token");
            scanQuery.setParameters(token);
            return scanQuery.executeUnique();
        } finally {
            trx.rollback();
        }
    }

    /**
     * Record the successful receipt of a {@link ScanStatus #SCAN_STATUS_COMPLETE} event for a given {@link VulnerabilityScan}.
     * <p>
     * This method expects that access to the {@link VulnerabilityScan} table is serialized
     * through Kafka events, keyed by the scan's token. This assumption allows for optimistic
     * locking to be used.
     *
     * @param scanToken The token that uniquely identifies the scan for clients
     * @param value
     * @return The updated {@link VulnerabilityScan}, or {@code null} when no {@link VulnerabilityScan} was found
     */
    public VulnerabilityScan recordVulnerabilityScanResult(final String scanToken, ScanResult value) {
        final Transaction trx = pm.currentTransaction();
        trx.setOptimistic(true);
        try {
            trx.begin();
            final Query<VulnerabilityScan> scanQuery = pm.newQuery(VulnerabilityScan.class);
            scanQuery.setFilter("token == :token");
            scanQuery.setParameters(scanToken);
            final VulnerabilityScan scan = scanQuery.executeUnique();
            if (scan == null) {
                return null;
            }
            final int received = scan.getReceivedResults() + 1;
            scan.setReceivedResults(received);
            final long failedScanCount = value.getScannerResultsList().stream()
                    .map(ScannerResult::getStatus)
                    .filter(SCAN_STATUS_FAILED::equals)
                    .count();
            scan.setScanFailed(scan.getScanFailed() + failedScanCount);
            scan.setScanTotal(value.getScannerResultsCount() + scan.getScanTotal());
            scan.setStatus(scan.getExpectedResults() - received == 0
                    ? VulnerabilityScan.Status.COMPLETED
                    : VulnerabilityScan.Status.IN_PROGRESS);
            scan.setUpdatedAt(new Date());
            trx.commit();
            return scan;
        } finally {
            if (trx.isActive()) {
                trx.rollback();
            }
        }
    }

    public VulnerableSoftware getVulnerableSoftwareByPurlAndVersion(String purlType, String purlNamespace, String purlName, String version) {
        return getVulnerableSoftwareQueryManager().getVulnerableSoftwareByPurlAndVersion(purlType, purlNamespace, purlName, version);
    }

    /**
     * Execute a give {@link Query} and ensure that resources associated with it are released post execution.
     *
     * @param query      The {@link Query} to execute
     * @param parameters The parameters of the query
     * @return The result of the query
     */
    public Object executeAndClose(final Query<?> query, final Object... parameters) {
        try {
            return query.executeWithArray(parameters);
        } finally {
            query.closeAll();
        }
    }

    public void createWorkflowSteps(UUID token) {
        getWorkflowStateQueryManager().createWorkflowSteps(token);
    }


    public List<WorkflowState> getAllWorkflowStatesForAToken(UUID token) {
        return getWorkflowStateQueryManager().getAllWorkflowStatesForAToken(token);
    }

    public List<WorkflowState> getAllDescendantWorkflowStatesOfParent(WorkflowState parent) {
        return getWorkflowStateQueryManager().getAllDescendantWorkflowStatesOfParent(parent);
    }

    public WorkflowState getWorkflowStateById(long id) {
        return getWorkflowStateQueryManager().getWorkflowState(id);
    }

    public WorkflowState updateWorkflowState(WorkflowState transientWorkflowState) {
        return getWorkflowStateQueryManager().updateWorkflowState(transientWorkflowState);
    }

    public int updateAllDescendantStatesOfParent(WorkflowState parentWorkflowState, WorkflowStatus transientStatus, Date updatedAt) {
        return getWorkflowStateQueryManager().updateAllDescendantStatesOfParent(parentWorkflowState, transientStatus, updatedAt);
    }

    public WorkflowState getWorkflowStateByTokenAndStep(UUID token, WorkflowStep workflowStep) {
        return getWorkflowStateQueryManager().getWorkflowStateByTokenAndStep(token, workflowStep);
    }

    public void deleteWorkflowState(WorkflowState workflowState) {
        getWorkflowStateQueryManager().deleteWorkflowState(workflowState);
    }

    public WorkflowState updateStartTimeIfWorkflowStateExists(UUID token, WorkflowStep workflowStep) {
        return getWorkflowStateQueryManager().updateStartTimeIfWorkflowStateExists(token, workflowStep);
    }
}
