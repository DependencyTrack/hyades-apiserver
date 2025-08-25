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
package org.dependencytrack.workflow;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.proto.internal.workflow.payload.v1.ProjectIdentity;
import org.dependencytrack.workflow.api.ActivityContext;
import org.dependencytrack.workflow.api.failure.TerminalApplicationFailureException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

public class UpdateProjectMetricsActivityTest extends PersistenceCapableTest {

    @Test
    public void shouldThrowWhenArgumentIsNull() {
        final var ctxMock = mock(ActivityContext.class);

        assertThatExceptionOfType(TerminalApplicationFailureException.class)
                .isThrownBy(() -> new UpdateProjectMetricsActivity().execute(ctxMock, null))
                .withMessage("No project provided");
    }

    @Test
    public void shouldThrowWhenProjectUuidIsInvalid() {
        final var ctxMock = mock(ActivityContext.class);

        final var argument = ProjectIdentity.newBuilder()
                .setUuid("invalid")
                .setName("acme-app")
                .setVersion("1.0.0")
                .build();

        assertThatExceptionOfType(TerminalApplicationFailureException.class)
                .isThrownBy(() -> new UpdateProjectMetricsActivity().execute(ctxMock, argument))
                .withMessage("Project UUID is invalid");
    }

    @Test
    public void shouldThrowWhenProjectDoesNotExist() {
        final var ctxMock = mock(ActivityContext.class);

        final var argument = ProjectIdentity.newBuilder()
                .setUuid("f83cdf40-07ad-4762-99cd-f454a10403b9")
                .setName("acme-app")
                .setVersion("1.0.0")
                .build();

        assertThatExceptionOfType(TerminalApplicationFailureException.class)
                .isThrownBy(() -> new UpdateProjectMetricsActivity().execute(ctxMock, argument))
                .withMessage("Project does not exist");
    }

}