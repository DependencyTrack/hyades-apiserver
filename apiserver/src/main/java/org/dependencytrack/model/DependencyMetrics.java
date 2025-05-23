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
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import org.jdbi.v3.core.mapper.reflect.ColumnName;

import jakarta.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Date;

/**
 * Metrics specific for dependencies (project/component relationship).
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DependencyMetrics implements Serializable {

    private static final long serialVersionUID = 5231823328085979791L;

    @JsonIgnore
    @NotNull
    private long projectId;

    @JsonIgnore
    @NotNull
    private long componentId;

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private int critical;

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private int high;

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private int medium;

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private int low;

    private Integer unassigned;

    private int vulnerabilities;

    private int suppressed;

    private Integer findingsTotal;

    private Integer findingsAudited;

    private Integer findingsUnaudited;

    private double inheritedRiskScore;

    private Integer policyViolationsFail;

    private Integer policyViolationsWarn;

    private Integer policyViolationsInfo;

    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsTotal;

    // New column, must allow nulls on existing databases)
    private Integer policyViolationsAudited;

    // New column, must allow nulls on existing databases)
    private Integer policyViolationsUnaudited;

    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsSecurityTotal;

    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsSecurityAudited;

    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsSecurityUnaudited;

    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsLicenseTotal;

    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsLicenseAudited;

    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsLicenseUnaudited;

    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsOperationalTotal;

    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsOperationalAudited;

    // New column, must allow nulls on existing data bases)
    private Integer policyViolationsOperationalUnaudited;

    @NotNull
    @Schema(type = "integer", format = "int64", requiredMode = Schema.RequiredMode.REQUIRED, description = "UNIX epoch timestamp in milliseconds")
    private Date firstOccurrence;

    @NotNull
    @Schema(type = "integer", format = "int64", requiredMode = Schema.RequiredMode.REQUIRED, description = "UNIX epoch timestamp in milliseconds")
    private Date lastOccurrence;

    public long getProjectId() {
        return projectId;
    }

    public void setProjectId(long projectId) {
        this.projectId = projectId;
    }

    public long getComponentId() {
        return componentId;
    }

    public void setComponentId(long componentId) {
        this.componentId = componentId;
    }

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
        return unassigned != null ? unassigned : 0;
    }

    public void setUnassigned(int unassigned) {
        this.unassigned = unassigned;
    }

    public int getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(int vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public int getSuppressed() {
        return suppressed;
    }

    public void setSuppressed(int suppressed) {
        this.suppressed = suppressed;
    }

    public int getFindingsTotal() {
        return findingsTotal != null ? findingsTotal : 0;
    }

    public void setFindingsTotal(int findingsTotal) {
        this.findingsTotal = findingsTotal;
    }

    public int getFindingsAudited() {
        return findingsAudited != null ? findingsAudited : 0;
    }

    public void setFindingsAudited(int findingsAudited) {
        this.findingsAudited = findingsAudited;
    }

    public int getFindingsUnaudited() {
        return findingsUnaudited != null ? findingsUnaudited : 0;
    }

    public void setFindingsUnaudited(int findingsUnaudited) {
        this.findingsUnaudited = findingsUnaudited;
    }

    @ColumnName("RISKSCORE")
    public double getInheritedRiskScore() {
        return inheritedRiskScore;
    }

    public void setInheritedRiskScore(double inheritedRiskScore) {
        this.inheritedRiskScore = inheritedRiskScore;
    }

    public int getPolicyViolationsFail() {
        return policyViolationsFail != null ? policyViolationsFail : 0;
    }

    public void setPolicyViolationsFail(int policyViolationsFail) {
        this.policyViolationsFail = policyViolationsFail;
    }

    public int getPolicyViolationsWarn() {
        return policyViolationsWarn != null ? policyViolationsWarn : 0;
    }

    public void setPolicyViolationsWarn(int policyViolationsWarn) {
        this.policyViolationsWarn = policyViolationsWarn;
    }

    public int getPolicyViolationsInfo() {
        return policyViolationsInfo != null ? policyViolationsInfo : 0;
    }

    public void setPolicyViolationsInfo(int policyViolationsInfo) {
        this.policyViolationsInfo = policyViolationsInfo;
    }

    public int getPolicyViolationsTotal() {
        return policyViolationsTotal != null ? policyViolationsTotal : 0;
    }

    public void setPolicyViolationsTotal(int policyViolationsTotal) {
        this.policyViolationsTotal = policyViolationsTotal;
    }

    public int getPolicyViolationsAudited() {
        return policyViolationsAudited != null ? policyViolationsAudited : 0;
    }

    public void setPolicyViolationsAudited(int policyViolationsAudited) {
        this.policyViolationsAudited = policyViolationsAudited;
    }

    public int getPolicyViolationsUnaudited() {
        return policyViolationsUnaudited != null ? policyViolationsUnaudited : 0;
    }

    public void setPolicyViolationsUnaudited(int policyViolationsUnaudited) {
        this.policyViolationsUnaudited = policyViolationsUnaudited;
    }

    public int getPolicyViolationsSecurityTotal() {
        return policyViolationsSecurityTotal != null ? policyViolationsSecurityTotal : 0;
    }

    public void setPolicyViolationsSecurityTotal(int policyViolationsSecurityTotal) {
        this.policyViolationsSecurityTotal = policyViolationsSecurityTotal;
    }

    public int getPolicyViolationsSecurityAudited() {
        return policyViolationsSecurityAudited != null ? policyViolationsSecurityAudited : 0;
    }

    public void setPolicyViolationsSecurityAudited(int policyViolationsSecurityAudited) {
        this.policyViolationsSecurityAudited = policyViolationsSecurityAudited;
    }

    public int getPolicyViolationsSecurityUnaudited() {
        return policyViolationsSecurityUnaudited != null ? policyViolationsSecurityUnaudited : 0;
    }

    public void setPolicyViolationsSecurityUnaudited(int policyViolationsSecurityUnaudited) {
        this.policyViolationsSecurityUnaudited = policyViolationsSecurityUnaudited;
    }

    public int getPolicyViolationsLicenseTotal() {
        return policyViolationsLicenseTotal != null ? policyViolationsLicenseTotal : 0;
    }

    public void setPolicyViolationsLicenseTotal(int policyViolationsLicenseTotal) {
        this.policyViolationsLicenseTotal = policyViolationsLicenseTotal;
    }

    public int getPolicyViolationsLicenseAudited() {
        return policyViolationsLicenseAudited != null ? policyViolationsLicenseAudited : 0;
    }

    public void setPolicyViolationsLicenseAudited(int policyViolationsLicenseAudited) {
        this.policyViolationsLicenseAudited = policyViolationsLicenseAudited;
    }

    public int getPolicyViolationsLicenseUnaudited() {
        return policyViolationsLicenseUnaudited != null ? policyViolationsLicenseUnaudited : 0;
    }

    public void setPolicyViolationsLicenseUnaudited(int policyViolationsLicenseUnaudited) {
        this.policyViolationsLicenseUnaudited = policyViolationsLicenseUnaudited;
    }

    public int getPolicyViolationsOperationalTotal() {
        return policyViolationsOperationalTotal != null ? policyViolationsOperationalTotal : 0;
    }

    public void setPolicyViolationsOperationalTotal(int policyViolationsOperationalTotal) {
        this.policyViolationsOperationalTotal = policyViolationsOperationalTotal;
    }

    public int getPolicyViolationsOperationalAudited() {
        return policyViolationsOperationalAudited != null ? policyViolationsOperationalAudited : 0;
    }

    public void setPolicyViolationsOperationalAudited(int policyViolationsOperationalAudited) {
        this.policyViolationsOperationalAudited = policyViolationsOperationalAudited;
    }

    public int getPolicyViolationsOperationalUnaudited() {
        return policyViolationsOperationalUnaudited != null ? policyViolationsOperationalUnaudited : 0;
    }

    public void setPolicyViolationsOperationalUnaudited(int policyViolationsOperationalUnaudited) {
        this.policyViolationsOperationalUnaudited = policyViolationsOperationalUnaudited;
    }

    public Date getFirstOccurrence() {
        return firstOccurrence;
    }

    public void setFirstOccurrence(Date firstOccurrence) {
        this.firstOccurrence = firstOccurrence;
    }

    public Date getLastOccurrence() {
        return lastOccurrence;
    }

    public void setLastOccurrence(Date lastOccurrence) {
        this.lastOccurrence = lastOccurrence;
    }
}
