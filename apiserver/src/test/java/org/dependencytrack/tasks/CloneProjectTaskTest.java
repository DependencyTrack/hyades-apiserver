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
package org.dependencytrack.tasks;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.CloneProjectEvent;
import org.dependencytrack.model.Project;
import org.dependencytrack.resources.v1.vo.CloneProjectRequest;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.WorkflowStatus.COMPLETED;
import static org.dependencytrack.model.WorkflowStatus.FAILED;
import static org.dependencytrack.model.WorkflowStep.PROJECT_CLONE;

public class CloneProjectTaskTest extends PersistenceCapableTest {

    @Test
    public void testCloneProjectTask() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        CloneProjectRequest request = new CloneProjectRequest(project.getUuid().toString(), "1.1", false, false, false, false, false, false, false, false, false);
        final var cloneProjectEvent = new CloneProjectEvent(request);
        new CloneProjectTask().inform(cloneProjectEvent);
        var clonedProject = qm.getProject("Acme Example", "1.1");
        assertThat(clonedProject).isNotNull();
        assertThat(qm.getAllWorkflowStatesForAToken(cloneProjectEvent.getChainIdentifier())).satisfiesExactly(
                state -> {
                    assertThat(state.getStep()).isEqualTo(PROJECT_CLONE);
                    assertThat(state.getStatus()).isEqualTo(COMPLETED);
                    assertThat(state.getStartedAt()).isNotNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                });

    }

    @Test
    public void testCloneProjectDoesNotExist() {
        var uuid = UUID.fromString("2a5ede59-e7d9-40c5-bb41-c9262b56e6cc");
        CloneProjectRequest request = new CloneProjectRequest(uuid.toString(), "1.1", false, false, false, false, false, false, false, false, false);
        final var cloneProjectEvent = new CloneProjectEvent(request);
        new CloneProjectTask().inform(cloneProjectEvent);
        var clonedProject = qm.getProject("Acme Example", "1.1");
        assertThat(clonedProject).isNull();
        assertThat(qm.getAllWorkflowStatesForAToken(cloneProjectEvent.getChainIdentifier())).satisfiesExactly(
                state -> {
                    assertThat(state.getStep()).isEqualTo(PROJECT_CLONE);
                    assertThat(state.getStatus()).isEqualTo(FAILED);
                    assertThat(state.getStartedAt()).isNotNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                    assertThat(state.getFailureReason()).contains(
                            "Source project does not exist");
                });
    }

    @Test
    public void testCloneProjectVersionExist() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        // Clone request with project version already existing.
        CloneProjectRequest request = new CloneProjectRequest(project.getUuid().toString(), "1.0", false, false, false, false, false, false, false, false, false);
        final var cloneProjectEvent = new CloneProjectEvent(request);
        new CloneProjectTask().inform(cloneProjectEvent);
        assertThat(qm.getAllWorkflowStatesForAToken(cloneProjectEvent.getChainIdentifier())).satisfiesExactly(
                state -> {
                    assertThat(state.getStep()).isEqualTo(PROJECT_CLONE);
                    assertThat(state.getStatus()).isEqualTo(FAILED);
                    assertThat(state.getStartedAt()).isNotNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                    assertThat(state.getFailureReason()).contains("Target project version already exists");
                });
    }
}
