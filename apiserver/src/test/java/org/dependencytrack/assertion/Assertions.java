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
package org.dependencytrack.assertion;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.fail;

public final class Assertions {

    private Assertions() {
    }

    /**
     * Assert that a condition becomes true within a given timeout.
     *
     * @param condition The condition to evaluate
     * @param timeout   The timeout to enforce
     * @throws InterruptedException When interrupted while sleeping in between evaluations
     */
    public static void assertConditionWithTimeout(final Supplier<Boolean> condition, final Duration timeout) throws InterruptedException {
        final var deadline = LocalDateTime.now().plus(timeout);

        while (LocalDateTime.now().isBefore(deadline)) {
            final Boolean conditionResult = condition.get();
            if (conditionResult != null && conditionResult) {
                return;
            }

            TimeUnit.MILLISECONDS.sleep(100);
        }

        fail("Timeout exceeded while waiting for condition to become true");
    }

}
