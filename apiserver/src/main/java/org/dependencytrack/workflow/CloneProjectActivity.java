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

import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.internal.workflow.payload.v1.CloneProjectArgs;
import org.dependencytrack.proto.internal.workflow.payload.v1.ProjectIdentity;
import org.dependencytrack.workflow.api.ActivityContext;
import org.dependencytrack.workflow.api.ActivityExecutor;
import org.dependencytrack.workflow.api.annotation.Activity;
import org.dependencytrack.workflow.api.failure.TerminalApplicationFailureException;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

import static org.dependencytrack.proto.internal.workflow.payload.v1.CloneProjectArgs.Include.INCLUDE_ACL;
import static org.dependencytrack.proto.internal.workflow.payload.v1.CloneProjectArgs.Include.INCLUDE_AUDIT_HISTORY;
import static org.dependencytrack.proto.internal.workflow.payload.v1.CloneProjectArgs.Include.INCLUDE_COMPONENTS;
import static org.dependencytrack.proto.internal.workflow.payload.v1.CloneProjectArgs.Include.INCLUDE_POLICY_VIOLATIONS;
import static org.dependencytrack.proto.internal.workflow.payload.v1.CloneProjectArgs.Include.INCLUDE_PROPERTIES;
import static org.dependencytrack.proto.internal.workflow.payload.v1.CloneProjectArgs.Include.INCLUDE_SERVICES;
import static org.dependencytrack.proto.internal.workflow.payload.v1.CloneProjectArgs.Include.INCLUDE_TAGS;
import static org.dependencytrack.workflow.mapping.PayloadModelConverter.convertToProjectIdentity;

/**
 * @since 5.7.0
 */
@Activity(name = "clone-project")
public final class CloneProjectActivity implements ActivityExecutor<CloneProjectArgs, ProjectIdentity> {

    private static final Logger LOGGER = LoggerFactory.getLogger(CloneProjectActivity.class);

    @Override
    public ProjectIdentity execute(
            final @NonNull ActivityContext ctx,
            final CloneProjectArgs args) throws Exception {
        if (args == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        final UUID sourceProjectUuid;
        try {
            sourceProjectUuid = UUID.fromString(args.getSourceProject().getUuid());
        } catch (IllegalArgumentException e) {
            throw new TerminalApplicationFailureException("Source project UUID is invalid", e);
        }

        final Project clonedProject;
        try (final var qm = new QueryManager()) {
            LOGGER.info("Cloning project {}", sourceProjectUuid);
            clonedProject = qm.clone(
                    sourceProjectUuid,
                    args.getTargetVersion(),
                    args.getIncludesList().contains(INCLUDE_TAGS),
                    args.getIncludesList().contains(INCLUDE_PROPERTIES),
                    args.getIncludesList().contains(INCLUDE_COMPONENTS),
                    args.getIncludesList().contains(INCLUDE_SERVICES),
                    args.getIncludesList().contains(INCLUDE_AUDIT_HISTORY),
                    args.getIncludesList().contains(INCLUDE_ACL),
                    args.getIncludesList().contains(INCLUDE_POLICY_VIOLATIONS),
                    args.getIsTargetVersionLatest());
        } catch (IllegalStateException e) {
            // TODO: Use explicit exception types to differentiate these scenarios.
            if (e.getMessage() != null
                && (e.getMessage().contains("does not exist anymore")
                    || e.getMessage().contains("that version already exists"))) {
                throw new TerminalApplicationFailureException("Project could not be cloned", e);
            }

            throw e;
        }

        return convertToProjectIdentity(clonedProject);
    }

}
