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

import alpine.common.logging.Logger;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Optional;

public class ProcessBomUploadWorkflowRunner implements WorkflowRunner<ObjectNode, Void> {

    private static final Logger LOGGER = Logger.getLogger(ProcessBomUploadWorkflowRunner.class);

    @Override
    public Optional<Void> run(final WorkflowRunContext<ObjectNode> ctx) throws Exception {
        try {
            ctx.callActivity("ingest-bom", "123", null, Void.class, null);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Failed to ingest BOM", e.getCause());
        }

        try {
            ctx.callActivity("evaluate-project-policies", "456", null, Void.class, null);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Failed to evaluate project policies", e.getCause());
        }

        try {
            ctx.callActivity("update-project-metrics", "789", null, Void.class, null);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Failed to update project metrics", e.getCause());
        }

        return Optional.empty();
    }

}
