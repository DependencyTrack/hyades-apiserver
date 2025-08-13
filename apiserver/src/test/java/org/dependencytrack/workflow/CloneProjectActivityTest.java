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

import org.dependencytrack.proto.internal.workflow.payload.v1.CloneProjectArgs;
import org.dependencytrack.proto.internal.workflow.payload.v1.ProjectIdentity;
import org.dependencytrack.workflow.api.ActivityContext;
import org.dependencytrack.workflow.api.failure.TerminalApplicationFailureException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

public class CloneProjectActivityTest {

    @Test
    public void shouldThrowWhenArgumentIsNull() {
        final var ctxMock = mock(ActivityContext.class);

        assertThatExceptionOfType(TerminalApplicationFailureException.class)
                .isThrownBy(() -> new CloneProjectActivity().execute(ctxMock, null))
                .withMessage("No argument provided");
    }

    @Test
    public void shouldThrowWhenProjectUuidIsInvalid() {
        final var ctxMock = mock(ActivityContext.class);

        final var argument = CloneProjectArgs.newBuilder()
                .setSourceProject(ProjectIdentity.newBuilder()
                        .setUuid("invalid")
                        .setName("acme-app")
                        .setVersion("1.0.0")
                        .build())
                .build();

        assertThatExceptionOfType(TerminalApplicationFailureException.class)
                .isThrownBy(() -> new CloneProjectActivity().execute(ctxMock, argument))
                .withMessage("Source project UUID is invalid");
    }

}