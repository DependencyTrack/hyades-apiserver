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
package org.dependencytrack.resources.v2;

import alpine.server.auth.PermissionRequired;
import org.dependencytrack.api.v2.WorkflowsApi;
import org.dependencytrack.api.v2.model.ListWorkflowStatesResponse;
import org.dependencytrack.api.v2.model.ListWorkflowStatesResponseItem;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.persistence.QueryManager;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Provider
public class WorkflowsResource implements WorkflowsApi {

    @Override
    @PermissionRequired(Permissions.Constants.BOM_UPLOAD)
    public Response getWorkflowStates(final UUID token) {
        List<WorkflowState> workflowStates;
        try (final var qm = new QueryManager()) {
            workflowStates = qm.getAllWorkflowStatesForAToken(token);
            if (workflowStates.isEmpty()) {
                throw new NotFoundException();
            }
        }
        List<ListWorkflowStatesResponseItem> states = workflowStates.stream()
                .map(this::mapWorkflowStateResponse)
                .collect(Collectors.toList());
        return Response.ok(ListWorkflowStatesResponse.builder().states(states).build()).build();
    }

    private ListWorkflowStatesResponseItem mapWorkflowStateResponse(WorkflowState workflowState) {
        var mappedState = ListWorkflowStatesResponseItem.builder()
                .token(workflowState.getToken())
                .status(ListWorkflowStatesResponseItem.StatusEnum.fromString(workflowState.getStatus().name()))
                .step(ListWorkflowStatesResponseItem.StepEnum.fromString(workflowState.getStep().name()))
                .failureReason(workflowState.getFailureReason())
                .build();
        if (workflowState.getStartedAt() != null) {
            mappedState.setStartedAt(workflowState.getStartedAt().getTime());
        }
        if (workflowState.getUpdatedAt() != null) {
            mappedState.setUpdatedAt(workflowState.getUpdatedAt().getTime());
        }
        return mappedState;
    }
}
