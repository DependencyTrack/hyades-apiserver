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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

public class WorkflowDaoTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private WorkflowDao workflowDao;

    @BeforeEach
    public void before() throws Exception {
        super.before();
        jdbiHandle = openJdbiHandle();
        workflowDao = jdbiHandle.attach(WorkflowDao.class);
    }

    @AfterEach
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
        super.after();
    }

    @Test
    public void shouldReturnTrueWhenPendingStateExists() {
        final var token = UUID.randomUUID();
        insertWorkflowState(token, "BOM_CONSUMPTION", "PENDING");

        assertThat(workflowDao.existsWithNonTerminalStatus(token)).isTrue();
    }

    @Test
    public void shouldReturnTrueWhenTimedOutStateExists() {
        final var token = UUID.randomUUID();
        insertWorkflowState(token, "BOM_CONSUMPTION", "TIMED_OUT");

        assertThat(workflowDao.existsWithNonTerminalStatus(token)).isTrue();
    }

    @Test
    public void shouldReturnFalseWhenOnlyTerminalStatesExist() {
        final var token = UUID.randomUUID();
        insertWorkflowState(token, "BOM_CONSUMPTION", "COMPLETED");
        insertWorkflowState(token, "BOM_PROCESSING", "FAILED");

        assertThat(workflowDao.existsWithNonTerminalStatus(token)).isFalse();
    }

    @Test
    public void shouldReturnFalseWhenNoStatesExist() {
        assertThat(workflowDao.existsWithNonTerminalStatus(UUID.randomUUID())).isFalse();
    }

    private void insertWorkflowState(UUID token, String step, String status) {
        jdbiHandle.execute("""
                INSERT INTO "WORKFLOW_STATE" ("STATUS", "STEP", "TOKEN", "UPDATED_AT")
                VALUES (?, ?, CAST(? AS UUID), NOW())
                """, status, step, token.toString());
    }

}
