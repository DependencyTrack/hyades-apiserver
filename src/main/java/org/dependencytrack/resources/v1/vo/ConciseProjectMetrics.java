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
package org.dependencytrack.resources.v1.vo;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import org.dependencytrack.persistence.jdbi.ProjectDao.ConciseProjectMetricsRow;

/**
 * @since 5.5.0
 */
@ApiModel(description = "A concise representation of a project's metrics")
public record ConciseProjectMetrics(
        @ApiModelProperty(value = "Total number of components", required = true) int components,
        @ApiModelProperty(value = "Number of vulnerabilities with critical severity", required = true) int critical,
        @ApiModelProperty(value = "Number of vulnerabilities with high severity", required = true) int high,
        @ApiModelProperty(value = "Number of vulnerabilities with low severity", required = true) int low,
        @ApiModelProperty(value = "Number of vulnerabilities with medium severity", required = true) int medium,
        @ApiModelProperty(value = "Number of policy violations with status FAIL", required = true) int policyViolationsFail,
        @ApiModelProperty(value = "Number of policy violations with status WARN", required = true) int policyViolationsInfo,
        @ApiModelProperty(value = "Number of license policy violations", required = true) int policyViolationsLicenseTotal,
        @ApiModelProperty(value = "Number of operational policy violations", required = true) int policyViolationsOperationalTotal,
        @ApiModelProperty(value = "Number of security policy violations", required = true) int policyViolationsSecurityTotal,
        @ApiModelProperty(value = "Total number of policy violations", required = true) int policyViolationsTotal,
        @ApiModelProperty(value = "Number of policy violations with status WARN", required = true) int policyViolationsWarn,
        @ApiModelProperty(value = "The inherited risk score", required = true) double inheritedRiskScore,
        @ApiModelProperty(value = "Number of vulnerabilities with unassigned severity", required = true) int unassigned,
        @ApiModelProperty(value = "Total number of vulnerabilities", required = true) int vulnerabilities
) {

    public ConciseProjectMetrics(final ConciseProjectMetricsRow row) {
        this(row.components(), row.critical(), row.high(), row.low(), row.medium(),
                row.policyViolationsFail(), row.policyViolationsInfo(), row.policyViolationsLicenseTotal(),
                row.policyViolationsOperationalTotal(), row.policyViolationsSecurityTotal(), row.policyViolationsTotal(),
                row.policyViolationsWarn(), row.riskScore(), row.unassigned(), row.vulnerabilities());
    }

}
