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
package org.dependencytrack.workflow.framework;

import java.time.Duration;

public record RetryPolicy(
        Duration initialDelay,
        double multiplier,
        double randomizationFactor,
        Duration maxDelay,
        int maxAttempts) {

    public static RetryPolicy defaultRetryPolicy() {
        return new RetryPolicy(Duration.ofSeconds(5), 1.5, 0.3, Duration.ofMinutes(30), -1);
    }

    public RetryPolicy withInitialDelay(final Duration initialDelay) {
        return new RetryPolicy(initialDelay, this.multiplier, this.randomizationFactor, this.maxDelay, this.maxAttempts);
    }

    public RetryPolicy withMultiplier(final double multiplier) {
        return new RetryPolicy(this.initialDelay, multiplier, this.randomizationFactor, this.maxDelay, this.maxAttempts);
    }

    public RetryPolicy withRandomizationFactor(final double randomizationFactor) {
        return new RetryPolicy(this.initialDelay, this.multiplier, randomizationFactor, this.maxDelay, this.maxAttempts);
    }

    public RetryPolicy withMaxDelay(final Duration maxDelay) {
        return new RetryPolicy(this.initialDelay, this.multiplier, this.randomizationFactor, maxDelay, this.maxAttempts);
    }

    public RetryPolicy withMaxAttempts(final int maxAttempts) {
        return new RetryPolicy(this.initialDelay, this.multiplier, this.randomizationFactor, this.maxDelay, maxAttempts);
    }

}
