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
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.WorkflowStatus.PENDING;
import static org.dependencytrack.model.WorkflowStep.BOM_CONSUMPTION;

public class WorkflowQueryManagerTest extends PersistenceCapableTest {

    @Test
    public void shouldReturnWorkflowStateForToken() {
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
    public void shouldNotReturnWorkflowStateForDifferentToken() {
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

        assertThat(qm.getAllWorkflowStatesForAToken(UUID.randomUUID())).isEmpty();
    }

    @Test
    public void shouldGetWorkflowStateByTokenAndStep() {
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

}
