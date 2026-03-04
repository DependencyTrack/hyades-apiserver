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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link RatingSource} precedence and overwrite logic.
 * Precedence order: POLICY > VEX > MANUAL > NVD
 */
class RatingSourceTest {

    @Test
    void testPrecedenceOrder() {
        // Verify precedence values are correctly ordered: POLICY > VEX > MANUAL > NVD
        assertTrue(RatingSource.POLICY.getPrecedence() > RatingSource.VEX.getPrecedence());
        assertTrue(RatingSource.VEX.getPrecedence() > RatingSource.MANUAL.getPrecedence());
        assertTrue(RatingSource.MANUAL.getPrecedence() > RatingSource.NVD.getPrecedence());
    }

    @Test
    void testCanOverwrite_PolicyOverwritesAll() {
        // POLICY should be able to overwrite everything (highest precedence)
        assertTrue(RatingSource.POLICY.canOverwrite(RatingSource.POLICY));
        assertTrue(RatingSource.POLICY.canOverwrite(RatingSource.VEX));
        assertTrue(RatingSource.POLICY.canOverwrite(RatingSource.MANUAL));
        assertTrue(RatingSource.POLICY.canOverwrite(RatingSource.NVD));
        assertTrue(RatingSource.POLICY.canOverwrite(null));
    }

    @Test
    void testCanOverwrite_VexOverwritesManualAndNvd() {
        // VEX should be able to overwrite itself, MANUAL, and NVD
        assertTrue(RatingSource.VEX.canOverwrite(RatingSource.VEX));
        assertTrue(RatingSource.VEX.canOverwrite(RatingSource.MANUAL));
        assertTrue(RatingSource.VEX.canOverwrite(RatingSource.NVD));
        assertTrue(RatingSource.VEX.canOverwrite(null));

        // VEX should NOT be able to overwrite POLICY
        assertFalse(RatingSource.VEX.canOverwrite(RatingSource.POLICY));
    }

    @Test
    void testCanOverwrite_ManualOverwritesOnlyNvd() {
        // MANUAL should be able to overwrite itself and NVD
        assertTrue(RatingSource.MANUAL.canOverwrite(RatingSource.MANUAL));
        assertTrue(RatingSource.MANUAL.canOverwrite(RatingSource.NVD));
        assertTrue(RatingSource.MANUAL.canOverwrite(null));

        // MANUAL should NOT be able to overwrite POLICY or VEX
        assertFalse(RatingSource.MANUAL.canOverwrite(RatingSource.POLICY));
        assertFalse(RatingSource.MANUAL.canOverwrite(RatingSource.VEX));
    }

    @Test
    void testCanOverwrite_NvdOverwritesOnlyItself() {
        // NVD should be able to overwrite itself and null
        assertTrue(RatingSource.NVD.canOverwrite(RatingSource.NVD));
        assertTrue(RatingSource.NVD.canOverwrite(null));

        // NVD should NOT be able to overwrite any higher precedence source
        assertFalse(RatingSource.NVD.canOverwrite(RatingSource.POLICY));
        assertFalse(RatingSource.NVD.canOverwrite(RatingSource.VEX));
        assertFalse(RatingSource.NVD.canOverwrite(RatingSource.MANUAL));
    }

    @Test
    void testCanOverwrite_NullSource() {
        // All sources should be able to overwrite null (no existing rating)
        assertTrue(RatingSource.POLICY.canOverwrite(null));
        assertTrue(RatingSource.VEX.canOverwrite(null));
        assertTrue(RatingSource.MANUAL.canOverwrite(null));
        assertTrue(RatingSource.NVD.canOverwrite(null));
    }

    @Test
    void testRealWorldScenario_PolicyEnforcesStandards() {
        // Scenario: Analyst manually sets score to 5.0
        // Later, organizational policy requires minimum 8.0 for this vulnerability type
        // POLICY should overwrite MANUAL to enforce security standards
        assertTrue(RatingSource.POLICY.canOverwrite(RatingSource.MANUAL),
                "POLICY should enforce organizational security standards over manual assessments");
    }

    @Test
    void testRealWorldScenario_VexOverridesManual() {
        // Scenario: Analyst manually sets score to 9.0
        // Later, authoritative VEX document provides context-aware score of 7.2
        // VEX should overwrite MANUAL as it represents authoritative assessment
        assertTrue(RatingSource.VEX.canOverwrite(RatingSource.MANUAL),
                "Authoritative VEX ratings should overwrite manual assessments");
    }

    @Test
    void testRealWorldScenario_PolicyNotOverwritableByManual() {
        // Scenario: Policy sets minimum score 8.0
        // Analyst tries to manually lower it to 5.0
        // MANUAL should NOT be able to overwrite POLICY (policy enforcement)
        assertFalse(RatingSource.MANUAL.canOverwrite(RatingSource.POLICY),
                "Manual assessments should not override organizational policies");
    }

    @Test
    void testRealWorldScenario_VexUpdatesVex() {
        // Scenario: First VEX import sets score to 7.2
        // Later, an updated VEX document with revised score 8.5 is imported
        // The new VEX rating should overwrite the old one
        assertTrue(RatingSource.VEX.canOverwrite(RatingSource.VEX),
                "Updated VEX ratings should overwrite previous VEX ratings");
    }

    @Test
    void testRealWorldScenario_PolicyCanBeUpdated() {
        // Scenario: Policy sets score to 8.0
        // Later, policy is updated to require score 9.0
        // POLICY should be able to update itself
        assertTrue(RatingSource.POLICY.canOverwrite(RatingSource.POLICY),
                "Policies should be updatable by newer policy versions");
    }
}
