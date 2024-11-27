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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.PersistenceCapableTest;
import org.jdbi.v3.core.Handle;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.WorkflowStatus.COMPLETED;
import static org.dependencytrack.model.WorkflowStep.BOM_CONSUMPTION;
import static org.dependencytrack.model.WorkflowStep.BOM_PROCESSING;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

public class WorkflowDaoTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private WorkflowDao workflowDao;
    private final UUID workflowUuid = UUID.randomUUID();

    @Before
    public void before() throws Exception {
        super.before();
        jdbiHandle = openJdbiHandle();
        workflowDao = jdbiHandle.attach(WorkflowDao.class);
    }

    @After
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
        super.after();
    }

    @Test
    public void testUpdateWorkflowState() {
        qm.createWorkflowSteps(workflowUuid);
        final var updatedWorkflow = workflowDao.updateState(
                BOM_CONSUMPTION, workflowUuid, COMPLETED, null);
        assertThat(updatedWorkflow.get()).satisfies(workflowState -> {
            assertThat(workflowState.getStatus()).isEqualTo(COMPLETED);
            assertThat(workflowState.getStep()).isEqualTo(BOM_CONSUMPTION);
            assertThat(workflowState.getUpdatedAt()).isNotNull();
        });
    }

    @Test
    public void testStartState() {
        qm.createWorkflowSteps(workflowUuid);
        var updatedWorkflow = workflowDao.startState(BOM_PROCESSING, workflowUuid);
        assertThat(updatedWorkflow.getStartedAt()).isNotNull();
    }
}