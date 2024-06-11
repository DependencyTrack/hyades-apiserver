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

import org.dependencytrack.persistence.QueryManager;

import org.junit.Assert;
import org.junit.Test;

import alpine.model.IConfigProperty;

import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_CRITICAL;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_HIGH;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_MEDIUM;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_LOW;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_UNASSIGNED;

import org.dependencytrack.PersistenceCapableTest;

public class MetricsTest extends PersistenceCapableTest{
    protected QueryManager qm;

    @Test
    public void testMetricCalculations() {
        double chml = Metrics.inheritedRiskScore(20, 10, 5, 1, 3);
        Assert.assertEquals(281, chml, 0);

        double ratio = Metrics.vulnerableComponentRatio(5, 100);
        Assert.assertEquals(0.05, ratio, 0);
    }

    @Test
    public void testCustomRiskScores(){
        qm.createConfigProperty(CUSTOM_RISK_SCORE_CRITICAL.getGroupName(), CUSTOM_RISK_SCORE_CRITICAL.getPropertyName(), "9", IConfigProperty.PropertyType.INTEGER, null);
        qm.createConfigProperty(CUSTOM_RISK_SCORE_HIGH.getGroupName(), CUSTOM_RISK_SCORE_HIGH.getPropertyName(), "8", IConfigProperty.PropertyType.INTEGER, null);
        qm.createConfigProperty(CUSTOM_RISK_SCORE_MEDIUM.getGroupName(), CUSTOM_RISK_SCORE_MEDIUM.getPropertyName(), "7", IConfigProperty.PropertyType.INTEGER, null);
        qm.createConfigProperty(CUSTOM_RISK_SCORE_LOW.getGroupName(), CUSTOM_RISK_SCORE_LOW.getPropertyName(), "6", IConfigProperty.PropertyType.INTEGER, null);
        qm.createConfigProperty(CUSTOM_RISK_SCORE_UNASSIGNED.getGroupName(), CUSTOM_RISK_SCORE_UNASSIGNED.getPropertyName(), "6", IConfigProperty.PropertyType.INTEGER, null);

        // 20*9+10*8+5*7+1*6+3*6 = 319
        double chml = Metrics.inheritedRiskScore(20, 10, 5, 1, 3);
        Assert.assertEquals(319, chml, 0);


    }
}
