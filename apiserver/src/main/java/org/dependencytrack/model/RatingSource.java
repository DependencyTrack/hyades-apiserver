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

/**
 * Defines the source of an analysis. Precedence: POLICY > VEX > MANUAL > NVD.
 *
 * @since 5.8.0
 */
public enum RatingSource {

    POLICY(4),
    VEX(3),
    MANUAL(2),
    NVD(1);

    private final int precedence;

    RatingSource(int precedence) {
        this.precedence = precedence;
    }

    public int getPrecedence() {
        return precedence;
    }

    public boolean hasHigherPrecedenceThan(RatingSource other) {
        return other == null || this.precedence > other.precedence;
    }

    public boolean hasHigherOrEqualPrecedenceThan(RatingSource other) {
        return other == null || this.precedence >= other.precedence;
    }

    public boolean canOverwrite(RatingSource other) {
        return hasHigherOrEqualPrecedenceThan(other);
    }

    public static boolean shouldAllowUpdate(RatingSource currentSource, RatingSource newSource) {
        if (newSource == null) {
            return false;
        }
        return currentSource == null || newSource.hasHigherOrEqualPrecedenceThan(currentSource);
    }
}
