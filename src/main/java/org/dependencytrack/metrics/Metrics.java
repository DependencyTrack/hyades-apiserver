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
package org.dependencytrack.metrics;

import org.datanucleus.metadata.StoredProcQueryParameterMode;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.StoredProcedures;
import org.dependencytrack.persistence.StoredProcedures.Procedure;

import java.util.UUID;

/**
 * Helper class for enhancing metrics.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class Metrics {

    private Metrics() {
    }

    public static double inheritedRiskScore(final int critical, final int high, final int medium, final int low, final int unassigned) {
        return (double) ((critical * 10) + (high * 5) + (medium * 3) + (low * 1) + (unassigned * 5));
    }

    public static double vulnerableComponentRatio(final int vulnerabilities, final int vulnerableComponents) {
        double ratio = 0.0;
        if (vulnerableComponents > 0) {
            ratio = (double) vulnerabilities / vulnerableComponents;
        }
        return ratio;
    }

    /**
     * Update metrics for the entire portfolio.
     * <p>
     * Note: This does not implicitly update metrics for all projects in the portfolio,
     * it merely aggregates all existing {@link ProjectMetrics}.
     *
     * @since 5.0.0
     */
    public static void updatePortfolioMetrics() {
        StoredProcedures.execute(Procedure.UPDATE_PORTFOLIO_METRICS);
    }

    /**
     * Update metrics for a given {@link Project}.
     * <p>
     * Note: This does not implicitly update metrics for all components in the project,
     * it merely aggregates all existing {@link DependencyMetrics}.
     *
     * @param projectUuid {@link UUID} of the {@link Project} to update metrics for
     * @since 5.0.0
     */
    public static void updateProjectMetrics(final UUID projectUuid) {
        StoredProcedures.execute(Procedure.UPDATE_PROJECT_METRICS, query -> {
            query.registerParameter(1, String.class, StoredProcQueryParameterMode.IN);
            query.setImplicitParameter(1, projectUuid.toString());
        });
    }

    /**
     * Update metrics for a given {@link Component}.
     *
     * @param componentUuid {@link UUID} of the {@link Component} to update metrics for
     * @since 5.0.0
     */
    public static void updateComponentMetrics(final UUID componentUuid) {
        StoredProcedures.execute(Procedure.UPDATE_COMPONENT_METRICS, query -> {
            query.registerParameter(1, String.class, StoredProcQueryParameterMode.IN);
            query.setImplicitParameter(1, componentUuid.toString());
        });
    }

}
