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

import alpine.resources.AlpineRequest;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class WorkflowStateQueryManager extends QueryManager implements IQueryManager {

    WorkflowStateQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    WorkflowStateQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    public List<WorkflowState> getAllWorkflowStatesForAToken(UUID token) {
        final Query<WorkflowState> query = pm.newQuery(WorkflowState.class, "this.token == :token");
        query.setParameters(token);
        return executeAndCloseList(query);
    }

    public WorkflowState getWorkflowStateByTokenAndStep(UUID token, WorkflowStep step) {
        final Query<WorkflowState> query = pm.newQuery(WorkflowState.class, "this.token == :token && this.step == :step");
        query.setParameters(token, step);
        return executeAndCloseUnique(query);
    }

    public WorkflowState updateStartTimeIfWorkflowStateExists(UUID token, WorkflowStep workflowStep) {
        final Query<WorkflowState> query = pm.newQuery(WorkflowState.class, "this.token == :token && this.step == :step");
        query.setParameters(token, workflowStep);
        final WorkflowState currentState = executeAndCloseUnique(query);
        if (currentState != null) {
            currentState.setStartedAt(Date.from(Instant.now()));
            return persist(currentState);
        }
        return null;
    }

    public void updateWorkflowStateToComplete(WorkflowState workflowState) {
        if (workflowState != null) {
            workflowState.setStatus(WorkflowStatus.COMPLETED);
            workflowState.setUpdatedAt(Date.from(Instant.now()));
            persist(workflowState);
        }
    }

    public void updateWorkflowStateToFailed(WorkflowState workflowState, String failureReason) {
        if (workflowState != null) {
            workflowState.setFailureReason(failureReason);
            workflowState.setUpdatedAt(Date.from(Instant.now()));
            workflowState.setStatus(WorkflowStatus.FAILED);
            persist(workflowState);
        }
    }
}
