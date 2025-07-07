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

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.WorkflowApi;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.persistence.QueryManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.UUID;

@Provider
public class WorkflowResource implements WorkflowApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowResource.class);

    @Override
    public Response getWorkflowStates(String uuid) {
        List<WorkflowState> workflowStates;
        try (final var qm = new QueryManager()) {
            workflowStates = qm.getAllWorkflowStatesForAToken(UUID.fromString(uuid));
            if (workflowStates.isEmpty()) {
                return Response.status(Response.Status.NOT_FOUND).entity("Provided token " + uuid + " does not exist.").build();
            }
        } catch (Exception e) {
            LOGGER.error("An error occurred while fetching workflow status", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
        return Response.ok(workflowStates).build();
    }
}
