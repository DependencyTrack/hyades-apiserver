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
package org.dependencytrack.workflow.engine.api;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class WorkflowRunStatusTest {

    @ParameterizedTest
    @CsvSource(value = {
            "PENDING, PENDING, false",
            "PENDING, RUNNING, true",
            "PENDING, SUSPENDED, false",
            "PENDING, CANCELED, true",
            "PENDING, COMPLETED, false",
            "PENDING, FAILED, false",
            "RUNNING, PENDING, false",
            "RUNNING, RUNNING, false",
            "RUNNING, SUSPENDED, true",
            "RUNNING, CANCELED, true",
            "RUNNING, COMPLETED, true",
            "RUNNING, FAILED, true",
            "SUSPENDED, PENDING, false",
            "SUSPENDED, RUNNING, true",
            "SUSPENDED, SUSPENDED, false",
            "SUSPENDED, CANCELED, true",
            "SUSPENDED, COMPLETED, false",
            "SUSPENDED, FAILED, false",
            "CANCELED, PENDING, false",
            "CANCELED, RUNNING, false",
            "CANCELED, SUSPENDED, false",
            "CANCELED, CANCELED, false",
            "CANCELED, COMPLETED, false",
            "CANCELED, FAILED, false",
            "COMPLETED, PENDING, false",
            "COMPLETED, RUNNING, false",
            "COMPLETED, SUSPENDED, false",
            "COMPLETED, CANCELED, false",
            "COMPLETED, COMPLETED, false",
            "COMPLETED, FAILED, false",
            "FAILED, PENDING, false",
            "FAILED, RUNNING, false",
            "FAILED, SUSPENDED, false",
            "FAILED, CANCELED, false",
            "FAILED, COMPLETED, false",
            "FAILED, FAILED, false",
    })
    void shouldOnlyAllowValidTransitions(
            final WorkflowRunStatus from,
            final WorkflowRunStatus to,
            final boolean allowed) {
        assertThat(from.canTransitionTo(to)).isEqualTo(allowed);
    }

    @ParameterizedTest
    @CsvSource(value = {
            "PENDING, false",
            "RUNNING, false",
            "SUSPENDED, false",
            "CANCELED, true",
            "COMPLETED, true",
            "FAILED, true"
    })
    void shouldDeclareTerminalStatuses(final WorkflowRunStatus status, final boolean terminal) {
        assertThat(status.isTerminal()).isEqualTo(terminal);
    }

}