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

import org.junit.Test;

import java.time.Duration;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;

public class AssertionsTest {

    @Test
    public void testAssertConditionWithTimeout() {
        assertThatNoException()
                .isThrownBy(() -> assertConditionWithTimeout(new TestSupplier(), Duration.ofMillis(500)));

        assertThatExceptionOfType(AssertionError.class)
                .isThrownBy(() -> assertConditionWithTimeout(() -> false, Duration.ofMillis(200)));
    }

    private static class TestSupplier implements Supplier<Boolean> {

        private static final int FALSE_INVOCATIONS = 2;
        private int invocations;

        @Override
        public Boolean get() {
            return invocations++ >= FALSE_INVOCATIONS;
        }

    }

}
