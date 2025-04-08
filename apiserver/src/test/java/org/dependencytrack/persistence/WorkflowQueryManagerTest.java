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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.WorkflowState;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.WorkflowStatus.CANCELLED;
import static org.dependencytrack.model.WorkflowStatus.PENDING;
import static org.dependencytrack.model.WorkflowStep.BOM_CONSUMPTION;
import static org.dependencytrack.model.WorkflowStep.BOM_PROCESSING;
import static org.dependencytrack.model.WorkflowStep.REPO_META_ANALYSIS;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class WorkflowQueryManagerTest extends PersistenceCapableTest {

    @Test
    public void testWorkflowStateIsCreated() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setParent(null);
        workflowState.setFailureReason(null);
        workflowState.setStep(BOM_CONSUMPTION);
        workflowState.setStatus(PENDING);
        workflowState.setToken(uuid);
        workflowState.setStartedAt(Date.from(Instant.now()));
        workflowState.setUpdatedAt(Date.from(Instant.now()));
        qm.persist(workflowState);

        assertThat(qm.getAllWorkflowStatesForAToken(uuid)).satisfiesExactly(
                state -> {
                    assertThat(state.getStatus()).isEqualTo(PENDING);
                    assertThat(state.getStep()).isEqualTo(BOM_CONSUMPTION);
                    assertThat(state.getFailureReason()).isNull();
                    assertThat(state.getParent()).isNull();
                    assertThat(state.getToken()).isEqualTo(uuid);
                }
        );
    }

    @Test
    public void testShouldNotReturnWorkflowStateIfTokenDoesNotMatch() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setParent(null);
        workflowState.setFailureReason(null);
        workflowState.setStep(BOM_CONSUMPTION);
        workflowState.setStatus(PENDING);
        workflowState.setToken(uuid);
        workflowState.setStartedAt(Date.from(Instant.now()));
        workflowState.setUpdatedAt(Date.from(Instant.now()));
        qm.persist(workflowState);

        //get states by a new token
        assertThat(qm.getAllWorkflowStatesForAToken(UUID.randomUUID())).isEmpty();
    }

    @Test
    public void testShouldGetWorkflowStateById() {

        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setParent(null);
        workflowState.setFailureReason(null);
        workflowState.setStep(BOM_CONSUMPTION);
        workflowState.setStatus(PENDING);
        workflowState.setToken(uuid);
        workflowState.setStartedAt(Date.from(Instant.now()));
        workflowState.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState result = qm.persist(workflowState);

        assertThat(qm.getWorkflowStateById(result.getId())).satisfies(
                state -> {
                    assertThat(state.getStatus()).isEqualTo(PENDING);
                    assertThat(state.getStep()).isEqualTo(BOM_CONSUMPTION);
                    assertThat(state.getFailureReason()).isNull();
                    assertThat(state.getParent()).isNull();
                    assertThat(state.getToken()).isEqualTo(uuid);
                }
        );
    }

    @Test
    public void testShouldGetWorkflowStateByTokenAndStep() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setFailureReason(null);
        workflowState.setStep(BOM_CONSUMPTION);
        workflowState.setStatus(PENDING);
        workflowState.setToken(uuid);
        workflowState.setUpdatedAt(new Date());

        WorkflowState result = qm.persist(workflowState);

        assertThat(qm.getWorkflowStateByTokenAndStep(uuid, BOM_CONSUMPTION)).isEqualTo(result);
    }

    @Test
    public void testGetWorkflowStatesHierarchically() {

        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState1 = new WorkflowState();
        workflowState1.setParent(null);
        workflowState1.setFailureReason(null);
        workflowState1.setStep(BOM_CONSUMPTION);
        workflowState1.setStatus(PENDING);
        workflowState1.setToken(uuid);
        workflowState1.setStartedAt(Date.from(Instant.now()));
        workflowState1.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState result1 = qm.persist(workflowState1);

        WorkflowState workflowState2 = new WorkflowState();
        workflowState2.setParent(result1);
        workflowState2.setFailureReason(null);
        workflowState2.setStep(BOM_PROCESSING);
        workflowState2.setStatus(PENDING);
        workflowState2.setToken(uuid);
        workflowState2.setStartedAt(Date.from(Instant.now()));
        workflowState2.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState result2 = qm.persist(workflowState2);

        WorkflowState workflowState3 = new WorkflowState();
        workflowState3.setParent(result2);
        workflowState3.setFailureReason(null);
        workflowState3.setStep(REPO_META_ANALYSIS);
        workflowState3.setStatus(PENDING);
        workflowState3.setToken(uuid);
        workflowState3.setStartedAt(Date.from(Instant.now()));
        workflowState3.setUpdatedAt(Date.from(Instant.now()));
        qm.persist(workflowState3);

        assertThat(qm.getAllDescendantWorkflowStatesOfParent(result1)).satisfiesExactlyInAnyOrder(
                state -> {
                    assertThat(state.getStatus()).isEqualTo(PENDING);
                    assertThat(state.getStep()).isEqualTo(BOM_PROCESSING);
                    assertThat(state.getParent().getId()).isEqualTo(result1.getId());
                    assertThat(state.getFailureReason()).isNull();
                    assertThat(state.getToken()).isEqualTo(uuid);
                },
                state -> {
                    assertThat(state.getStatus()).isEqualTo(PENDING);
                    assertThat(state.getStep()).isEqualTo(REPO_META_ANALYSIS);
                    assertThat(state.getParent().getId()).isEqualTo(result2.getId());
                    assertThat(state.getFailureReason()).isNull();
                    assertThat(state.getToken()).isEqualTo(uuid);
                }
        );
    }

    @Test
    public void testUpdateWorkflowStatesOfAllDescendants() {

        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState1 = new WorkflowState();
        workflowState1.setParent(null);
        workflowState1.setFailureReason(null);
        workflowState1.setStep(BOM_CONSUMPTION);
        workflowState1.setStatus(PENDING);
        workflowState1.setToken(uuid);
        workflowState1.setStartedAt(Date.from(Instant.now()));
        workflowState1.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState result1 = qm.persist(workflowState1);

        WorkflowState workflowState2 = new WorkflowState();
        workflowState2.setParent(result1);
        workflowState2.setFailureReason(null);
        workflowState2.setStep(BOM_PROCESSING);
        workflowState2.setStatus(PENDING);
        workflowState2.setToken(uuid);
        workflowState2.setStartedAt(Date.from(Instant.now()));
        workflowState2.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState result2 = qm.persist(workflowState2);

        WorkflowState workflowState3 = new WorkflowState();
        workflowState3.setParent(result2);
        workflowState3.setFailureReason(null);
        workflowState3.setStep(REPO_META_ANALYSIS);
        workflowState3.setStatus(PENDING);
        workflowState3.setToken(uuid);
        workflowState3.setStartedAt(Date.from(Instant.now()));
        workflowState3.setUpdatedAt(Date.from(Instant.now()));
        qm.persist(workflowState3);

        assertThat(qm.updateAllDescendantStatesOfParent(result1, CANCELLED, Date.from(Instant.now()))).isEqualTo(2);
    }

    @Test
    public void testThrowsExceptionIfParentWorkflowStateIdIsMissing() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState1 = new WorkflowState();
        workflowState1.setStep(BOM_CONSUMPTION);
        workflowState1.setStatus(PENDING);
        workflowState1.setToken(uuid);
        workflowState1.setUpdatedAt(new Date());
        WorkflowState result1 = qm.persist(workflowState1);

        result1.setId(0);
        assertThrows(IllegalArgumentException.class, () -> qm.getAllDescendantWorkflowStatesOfParent(null));
        assertThrows(IllegalArgumentException.class, () -> qm.getAllDescendantWorkflowStatesOfParent(result1));
    }

    @Test
    public void testWorkflowStateIsDeleted() {
        UUID uuid = UUID.randomUUID();
        WorkflowState workflowState = new WorkflowState();
        workflowState.setParent(null);
        workflowState.setFailureReason(null);
        workflowState.setStep(BOM_CONSUMPTION);
        workflowState.setStatus(PENDING);
        workflowState.setToken(uuid);
        workflowState.setStartedAt(Date.from(Instant.now()));
        workflowState.setUpdatedAt(Date.from(Instant.now()));
        WorkflowState persisted = qm.persist(workflowState);

        qm.deleteWorkflowState(persisted);
        assertThat(qm.getWorkflowStateById(persisted.getId())).isNull();
    }
}
