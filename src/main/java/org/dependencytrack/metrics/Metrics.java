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
package org.dependencytrack.metrics;

import alpine.common.logging.Logger;
import org.datanucleus.metadata.StoredProcQueryParameterMode;
import org.dependencytrack.util.PersistenceUtil;

import java.util.UUID;

/**
 * Helper class for enhancing metrics.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class Metrics {

    private static final Logger LOGGER = Logger.getLogger(Metrics.class);

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

    public static void updatePortfolioMetrics() {
        LOGGER.info("Updating portfolio metrics");
        PersistenceUtil.executeStoredProcedure("UPDATE_PORTFOLIO_METRICS");
        LOGGER.info("Updating portfolio metrics completed");
    }

    public static void updateProjectMetrics(final UUID projectUuid) {
        LOGGER.info("Updating metrics of project " + projectUuid);
        PersistenceUtil.executeStoredProcedure("UPDATE_PROJECT_METRICS", query -> {
            query.registerParameter(1, String.class, StoredProcQueryParameterMode.IN);
            query.setImplicitParameter(1, projectUuid.toString());
        });
    }

    public static void updateComponentMetrics(final UUID componentUuid) {
        LOGGER.debug("Updating metrics of component " + componentUuid);
        PersistenceUtil.executeStoredProcedure("UPDATE_COMPONENT_METRICS", query -> {
            query.registerParameter(1, String.class, StoredProcQueryParameterMode.IN);
            query.setImplicitParameter(1, componentUuid.toString());
        });
    }

}
