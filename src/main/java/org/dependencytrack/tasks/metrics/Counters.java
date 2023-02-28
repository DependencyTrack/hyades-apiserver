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
package org.dependencytrack.tasks.metrics;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;

import java.util.Date;

/**
 * A utility class holding various counter variables.
 * <p>
 * It is used during metrics calculations to keep track of metric values.
 *
 * @since 4.6.0
 */
public final class Counters {

    int critical, high, medium, low, unassigned;
    double inheritedRiskScore;
    int components, vulnerableComponents, projects, vulnerableProjects;
    int vulnerabilities, suppressions, findingsTotal, findingsAudited, findingsUnaudited;
    int policyViolationsFail, policyViolationsWarn, policyViolationsInfo,
            policyViolationsTotal, policyViolationsAudited, policyViolationsUnaudited,
            policyViolationsSecurityTotal, policyViolationsSecurityAudited, policyViolationsSecurityUnaudited,
            policyViolationsLicenseTotal, policyViolationsLicenseAudited, policyViolationsLicenseUnaudited,
            policyViolationsOperationalTotal, policyViolationsOperationalAudited, policyViolationsOperationalUnaudited;

    public int getCritical() {
        return critical;
    }

    public void setCritical(int critical) {
        this.critical = critical;
    }

    public int getHigh() {
        return high;
    }

    public void setHigh(int high) {
        this.high = high;
    }

    public int getMedium() {
        return medium;
    }

    public void setMedium(int medium) {
        this.medium = medium;
    }

    public int getLow() {
        return low;
    }

    public void setLow(int low) {
        this.low = low;
    }

    public int getUnassigned() {
        return unassigned;
    }

    public void setUnassigned(int unassigned) {
        this.unassigned = unassigned;
    }

    public double getInheritedRiskScore() {
        return inheritedRiskScore;
    }

    public void setInheritedRiskScore(double inheritedRiskScore) {
        this.inheritedRiskScore = inheritedRiskScore;
    }

    public int getComponents() {
        return components;
    }

    public void setComponents(int components) {
        this.components = components;
    }

    public int getVulnerableComponents() {
        return vulnerableComponents;
    }

    public void setVulnerableComponents(int vulnerableComponents) {
        this.vulnerableComponents = vulnerableComponents;
    }

    public int getProjects() {
        return projects;
    }

    public void setProjects(int projects) {
        this.projects = projects;
    }

    public int getVulnerableProjects() {
        return vulnerableProjects;
    }

    public void setVulnerableProjects(int vulnerableProjects) {
        this.vulnerableProjects = vulnerableProjects;
    }

    public int getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(int vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public int getSuppressions() {
        return suppressions;
    }

    public void setSuppressions(int suppressions) {
        this.suppressions = suppressions;
    }

    public int getFindingsTotal() {
        return findingsTotal;
    }

    public void setFindingsTotal(int findingsTotal) {
        this.findingsTotal = findingsTotal;
    }

    public int getFindingsAudited() {
        return findingsAudited;
    }

    public void setFindingsAudited(int findingsAudited) {
        this.findingsAudited = findingsAudited;
    }

    public int getFindingsUnaudited() {
        return findingsUnaudited;
    }

    public void setFindingsUnaudited(int findingsUnaudited) {
        this.findingsUnaudited = findingsUnaudited;
    }

    public int getPolicyViolationsFail() {
        return policyViolationsFail;
    }

    public void setPolicyViolationsFail(int policyViolationsFail) {
        this.policyViolationsFail = policyViolationsFail;
    }

    public int getPolicyViolationsWarn() {
        return policyViolationsWarn;
    }

    public void setPolicyViolationsWarn(int policyViolationsWarn) {
        this.policyViolationsWarn = policyViolationsWarn;
    }

    public int getPolicyViolationsInfo() {
        return policyViolationsInfo;
    }

    public void setPolicyViolationsInfo(int policyViolationsInfo) {
        this.policyViolationsInfo = policyViolationsInfo;
    }

    public int getPolicyViolationsTotal() {
        return policyViolationsTotal;
    }

    public void setPolicyViolationsTotal(int policyViolationsTotal) {
        this.policyViolationsTotal = policyViolationsTotal;
    }

    public int getPolicyViolationsAudited() {
        return policyViolationsAudited;
    }

    public void setPolicyViolationsAudited(int policyViolationsAudited) {
        this.policyViolationsAudited = policyViolationsAudited;
    }

    public int getPolicyViolationsUnaudited() {
        return policyViolationsUnaudited;
    }

    public void setPolicyViolationsUnaudited(int policyViolationsUnaudited) {
        this.policyViolationsUnaudited = policyViolationsUnaudited;
    }

    public int getPolicyViolationsSecurityTotal() {
        return policyViolationsSecurityTotal;
    }

    public void setPolicyViolationsSecurityTotal(int policyViolationsSecurityTotal) {
        this.policyViolationsSecurityTotal = policyViolationsSecurityTotal;
    }

    public int getPolicyViolationsSecurityAudited() {
        return policyViolationsSecurityAudited;
    }

    public void setPolicyViolationsSecurityAudited(int policyViolationsSecurityAudited) {
        this.policyViolationsSecurityAudited = policyViolationsSecurityAudited;
    }

    public int getPolicyViolationsSecurityUnaudited() {
        return policyViolationsSecurityUnaudited;
    }

    public void setPolicyViolationsSecurityUnaudited(int policyViolationsSecurityUnaudited) {
        this.policyViolationsSecurityUnaudited = policyViolationsSecurityUnaudited;
    }

    public int getPolicyViolationsLicenseTotal() {
        return policyViolationsLicenseTotal;
    }

    public void setPolicyViolationsLicenseTotal(int policyViolationsLicenseTotal) {
        this.policyViolationsLicenseTotal = policyViolationsLicenseTotal;
    }

    public int getPolicyViolationsLicenseAudited() {
        return policyViolationsLicenseAudited;
    }

    public void setPolicyViolationsLicenseAudited(int policyViolationsLicenseAudited) {
        this.policyViolationsLicenseAudited = policyViolationsLicenseAudited;
    }

    public int getPolicyViolationsLicenseUnaudited() {
        return policyViolationsLicenseUnaudited;
    }

    public void setPolicyViolationsLicenseUnaudited(int policyViolationsLicenseUnaudited) {
        this.policyViolationsLicenseUnaudited = policyViolationsLicenseUnaudited;
    }

    public int getPolicyViolationsOperationalTotal() {
        return policyViolationsOperationalTotal;
    }

    public void setPolicyViolationsOperationalTotal(int policyViolationsOperationalTotal) {
        this.policyViolationsOperationalTotal = policyViolationsOperationalTotal;
    }

    public int getPolicyViolationsOperationalAudited() {
        return policyViolationsOperationalAudited;
    }

    public void setPolicyViolationsOperationalAudited(int policyViolationsOperationalAudited) {
        this.policyViolationsOperationalAudited = policyViolationsOperationalAudited;
    }

    public int getPolicyViolationsOperationalUnaudited() {
        return policyViolationsOperationalUnaudited;
    }

    public void setPolicyViolationsOperationalUnaudited(int policyViolationsOperationalUnaudited) {
        this.policyViolationsOperationalUnaudited = policyViolationsOperationalUnaudited;
    }

    public Date getMeasuredAt() {
        return measuredAt;
    }

    final Date measuredAt;

    public Counters() {
        this.measuredAt = new Date();
    }

    public DependencyMetrics createComponentMetrics(final Component component) {
        final var metrics = new DependencyMetrics();
        metrics.setComponent(component);
        metrics.setProject(component.getProject());
        metrics.setCritical(this.critical);
        metrics.setHigh(this.high);
        metrics.setMedium(this.medium);
        metrics.setLow(this.low);
        metrics.setUnassigned(this.unassigned);
        metrics.setVulnerabilities(this.vulnerabilities);
        metrics.setSuppressed(this.suppressions);
        metrics.setFindingsTotal(this.findingsTotal);
        metrics.setFindingsAudited(this.findingsAudited);
        metrics.setFindingsUnaudited(this.findingsUnaudited);
        metrics.setInheritedRiskScore(this.inheritedRiskScore);
        metrics.setPolicyViolationsFail(this.policyViolationsFail);
        metrics.setPolicyViolationsWarn(this.policyViolationsWarn);
        metrics.setPolicyViolationsInfo(this.policyViolationsInfo);
        metrics.setPolicyViolationsTotal(this.policyViolationsTotal);
        metrics.setPolicyViolationsAudited(this.policyViolationsAudited);
        metrics.setPolicyViolationsUnaudited(this.policyViolationsUnaudited);
        metrics.setPolicyViolationsSecurityTotal(this.policyViolationsSecurityTotal);
        metrics.setPolicyViolationsSecurityAudited(this.policyViolationsSecurityAudited);
        metrics.setPolicyViolationsSecurityUnaudited(this.policyViolationsSecurityUnaudited);
        metrics.setPolicyViolationsLicenseTotal(this.policyViolationsLicenseTotal);
        metrics.setPolicyViolationsLicenseAudited(this.policyViolationsLicenseAudited);
        metrics.setPolicyViolationsLicenseUnaudited(this.policyViolationsLicenseUnaudited);
        metrics.setPolicyViolationsOperationalTotal(this.policyViolationsOperationalTotal);
        metrics.setPolicyViolationsOperationalAudited(this.policyViolationsOperationalAudited);
        metrics.setPolicyViolationsOperationalUnaudited(this.policyViolationsOperationalUnaudited);
        metrics.setFirstOccurrence(this.measuredAt);
        metrics.setLastOccurrence(this.measuredAt);
        return metrics;
    }

    public ProjectMetrics createProjectMetrics(final Project project) {
        final var metrics = new ProjectMetrics();
        metrics.setProject(project);
        metrics.setCritical(this.critical);
        metrics.setHigh(this.high);
        metrics.setMedium(this.medium);
        metrics.setLow(this.low);
        metrics.setUnassigned(this.unassigned);
        metrics.setVulnerabilities(this.vulnerabilities);
        metrics.setComponents(this.components);
        metrics.setVulnerableComponents(this.vulnerableComponents);
        metrics.setSuppressed(this.suppressions);
        metrics.setFindingsTotal(this.findingsTotal);
        metrics.setFindingsAudited(this.findingsAudited);
        metrics.setFindingsUnaudited(this.findingsUnaudited);
        metrics.setInheritedRiskScore(this.inheritedRiskScore);
        metrics.setPolicyViolationsFail(this.policyViolationsFail);
        metrics.setPolicyViolationsWarn(this.policyViolationsWarn);
        metrics.setPolicyViolationsInfo(this.policyViolationsInfo);
        metrics.setPolicyViolationsTotal(this.policyViolationsTotal);
        metrics.setPolicyViolationsAudited(this.policyViolationsAudited);
        metrics.setPolicyViolationsUnaudited(this.policyViolationsUnaudited);
        metrics.setPolicyViolationsSecurityTotal(this.policyViolationsSecurityTotal);
        metrics.setPolicyViolationsSecurityAudited(this.policyViolationsSecurityAudited);
        metrics.setPolicyViolationsSecurityUnaudited(this.policyViolationsSecurityUnaudited);
        metrics.setPolicyViolationsLicenseTotal(this.policyViolationsLicenseTotal);
        metrics.setPolicyViolationsLicenseAudited(this.policyViolationsLicenseAudited);
        metrics.setPolicyViolationsLicenseUnaudited(this.policyViolationsLicenseUnaudited);
        metrics.setPolicyViolationsOperationalTotal(this.policyViolationsOperationalTotal);
        metrics.setPolicyViolationsOperationalAudited(this.policyViolationsOperationalAudited);
        metrics.setPolicyViolationsOperationalUnaudited(this.policyViolationsOperationalUnaudited);
        metrics.setFirstOccurrence(this.measuredAt);
        metrics.setLastOccurrence(this.measuredAt);
        return metrics;
    }

    public PortfolioMetrics createPortfolioMetrics() {
        final var metrics = new PortfolioMetrics();
        metrics.setCritical(this.critical);
        metrics.setHigh(this.high);
        metrics.setMedium(this.medium);
        metrics.setLow(this.low);
        metrics.setUnassigned(this.unassigned);
        metrics.setVulnerabilities(this.vulnerabilities);
        metrics.setComponents(this.components);
        metrics.setVulnerableComponents(this.vulnerableComponents);
        metrics.setSuppressed(this.suppressions);
        metrics.setFindingsTotal(this.findingsTotal);
        metrics.setFindingsAudited(this.findingsAudited);
        metrics.setFindingsUnaudited(this.findingsUnaudited);
        metrics.setProjects(this.projects);
        metrics.setVulnerableProjects(this.vulnerableProjects);
        metrics.setInheritedRiskScore(this.inheritedRiskScore);
        metrics.setPolicyViolationsFail(this.policyViolationsFail);
        metrics.setPolicyViolationsWarn(this.policyViolationsWarn);
        metrics.setPolicyViolationsInfo(this.policyViolationsInfo);
        metrics.setPolicyViolationsTotal(this.policyViolationsTotal);
        metrics.setPolicyViolationsAudited(this.policyViolationsAudited);
        metrics.setPolicyViolationsUnaudited(this.policyViolationsUnaudited);
        metrics.setPolicyViolationsSecurityTotal(this.policyViolationsSecurityTotal);
        metrics.setPolicyViolationsSecurityAudited(this.policyViolationsSecurityAudited);
        metrics.setPolicyViolationsSecurityUnaudited(this.policyViolationsSecurityUnaudited);
        metrics.setPolicyViolationsLicenseTotal(this.policyViolationsLicenseTotal);
        metrics.setPolicyViolationsLicenseAudited(this.policyViolationsLicenseAudited);
        metrics.setPolicyViolationsLicenseUnaudited(this.policyViolationsLicenseUnaudited);
        metrics.setPolicyViolationsOperationalTotal(this.policyViolationsOperationalTotal);
        metrics.setPolicyViolationsOperationalAudited(this.policyViolationsOperationalAudited);
        metrics.setPolicyViolationsOperationalUnaudited(this.policyViolationsOperationalUnaudited);
        metrics.setFirstOccurrence(this.measuredAt);
        metrics.setLastOccurrence(this.measuredAt);
        return metrics;
    }

    public boolean hasChanged(final DependencyMetrics comparedTo) {
        return comparedTo == null
                || comparedTo.getCritical() != this.critical
                || comparedTo.getHigh() != this.high
                || comparedTo.getMedium() != this.medium
                || comparedTo.getLow() != this.low
                || comparedTo.getUnassigned() != this.unassigned
                || comparedTo.getVulnerabilities() != this.vulnerabilities
                || comparedTo.getSuppressed() != this.suppressions
                || comparedTo.getFindingsTotal() != this.findingsTotal
                || comparedTo.getFindingsAudited() != this.findingsAudited
                || comparedTo.getFindingsUnaudited() != this.findingsUnaudited
                || comparedTo.getInheritedRiskScore() != this.inheritedRiskScore
                || comparedTo.getPolicyViolationsFail() != this.policyViolationsFail
                || comparedTo.getPolicyViolationsWarn() != this.policyViolationsWarn
                || comparedTo.getPolicyViolationsInfo() != this.policyViolationsInfo
                || comparedTo.getPolicyViolationsTotal() != this.policyViolationsTotal
                || comparedTo.getPolicyViolationsAudited() != this.policyViolationsAudited
                || comparedTo.getPolicyViolationsUnaudited() != this.policyViolationsUnaudited
                || comparedTo.getPolicyViolationsSecurityTotal() != this.policyViolationsSecurityTotal
                || comparedTo.getPolicyViolationsSecurityAudited() != this.policyViolationsSecurityAudited
                || comparedTo.getPolicyViolationsSecurityUnaudited() != this.policyViolationsSecurityUnaudited
                || comparedTo.getPolicyViolationsLicenseTotal() != this.policyViolationsLicenseTotal
                || comparedTo.getPolicyViolationsLicenseAudited() != this.policyViolationsLicenseAudited
                || comparedTo.getPolicyViolationsLicenseUnaudited() != this.policyViolationsLicenseUnaudited
                || comparedTo.getPolicyViolationsOperationalTotal() != this.policyViolationsOperationalTotal
                || comparedTo.getPolicyViolationsOperationalAudited() != this.policyViolationsOperationalAudited
                || comparedTo.getPolicyViolationsOperationalUnaudited() != this.policyViolationsOperationalUnaudited;
    }

    public boolean hasChanged(final ProjectMetrics comparedTo) {
        return comparedTo == null
                || comparedTo.getCritical() != this.critical
                || comparedTo.getHigh() != this.high
                || comparedTo.getMedium() != this.medium
                || comparedTo.getLow() != this.low
                || comparedTo.getUnassigned() != this.unassigned
                || comparedTo.getVulnerabilities() != this.vulnerabilities
                || comparedTo.getSuppressed() != this.suppressions
                || comparedTo.getFindingsTotal() != this.findingsTotal
                || comparedTo.getFindingsAudited() != this.findingsAudited
                || comparedTo.getFindingsUnaudited() != this.findingsUnaudited
                || comparedTo.getInheritedRiskScore() != this.inheritedRiskScore
                || comparedTo.getPolicyViolationsFail() != this.policyViolationsFail
                || comparedTo.getPolicyViolationsWarn() != this.policyViolationsWarn
                || comparedTo.getPolicyViolationsInfo() != this.policyViolationsInfo
                || comparedTo.getPolicyViolationsTotal() != this.policyViolationsTotal
                || comparedTo.getPolicyViolationsAudited() != this.policyViolationsAudited
                || comparedTo.getPolicyViolationsUnaudited() != this.policyViolationsUnaudited
                || comparedTo.getPolicyViolationsSecurityTotal() != this.policyViolationsSecurityTotal
                || comparedTo.getPolicyViolationsSecurityAudited() != this.policyViolationsSecurityAudited
                || comparedTo.getPolicyViolationsSecurityUnaudited() != this.policyViolationsSecurityUnaudited
                || comparedTo.getPolicyViolationsLicenseTotal() != this.policyViolationsLicenseTotal
                || comparedTo.getPolicyViolationsLicenseAudited() != this.policyViolationsLicenseAudited
                || comparedTo.getPolicyViolationsLicenseUnaudited() != this.policyViolationsLicenseUnaudited
                || comparedTo.getPolicyViolationsOperationalTotal() != this.policyViolationsOperationalTotal
                || comparedTo.getPolicyViolationsOperationalAudited() != this.policyViolationsOperationalAudited
                || comparedTo.getPolicyViolationsOperationalUnaudited() != this.policyViolationsOperationalUnaudited
                || comparedTo.getComponents() != this.components
                || comparedTo.getVulnerableComponents() != this.vulnerableComponents;
    }

    public boolean hasChanged(final PortfolioMetrics comparedTo) {
        return comparedTo == null
                || comparedTo.getCritical() != this.critical
                || comparedTo.getHigh() != this.high
                || comparedTo.getMedium() != this.medium
                || comparedTo.getLow() != this.low
                || comparedTo.getUnassigned() != this.unassigned
                || comparedTo.getVulnerabilities() != this.vulnerabilities
                || comparedTo.getInheritedRiskScore() != this.inheritedRiskScore
                || comparedTo.getPolicyViolationsFail() != this.policyViolationsFail
                || comparedTo.getPolicyViolationsWarn() != this.policyViolationsWarn
                || comparedTo.getPolicyViolationsInfo() != this.policyViolationsInfo
                || comparedTo.getPolicyViolationsTotal() != this.policyViolationsTotal
                || comparedTo.getPolicyViolationsAudited() != this.policyViolationsAudited
                || comparedTo.getPolicyViolationsUnaudited() != this.policyViolationsUnaudited
                || comparedTo.getPolicyViolationsSecurityTotal() != this.policyViolationsSecurityTotal
                || comparedTo.getPolicyViolationsSecurityAudited() != this.policyViolationsSecurityAudited
                || comparedTo.getPolicyViolationsSecurityUnaudited() != this.policyViolationsSecurityUnaudited
                || comparedTo.getPolicyViolationsLicenseTotal() != this.policyViolationsLicenseTotal
                || comparedTo.getPolicyViolationsLicenseAudited() != this.policyViolationsLicenseAudited
                || comparedTo.getPolicyViolationsLicenseUnaudited() != this.policyViolationsLicenseUnaudited
                || comparedTo.getPolicyViolationsOperationalTotal() != this.policyViolationsOperationalTotal
                || comparedTo.getPolicyViolationsOperationalAudited() != this.policyViolationsOperationalAudited
                || comparedTo.getPolicyViolationsOperationalUnaudited() != this.policyViolationsOperationalUnaudited
                || comparedTo.getComponents() != this.components
                || comparedTo.getVulnerableComponents() != this.vulnerableComponents
                || comparedTo.getSuppressed() != this.suppressions
                || comparedTo.getFindingsTotal() != this.findingsTotal
                || comparedTo.getFindingsAudited() != this.findingsAudited
                || comparedTo.getFindingsUnaudited() != this.findingsUnaudited
                || comparedTo.getProjects() != this.projects
                || comparedTo.getVulnerableProjects() != this.vulnerableProjects;
    }

}
