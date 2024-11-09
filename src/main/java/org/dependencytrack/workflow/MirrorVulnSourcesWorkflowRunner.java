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

import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.tasks.EpssMirrorTask;
import org.dependencytrack.tasks.NistMirrorTask;

import java.util.Optional;
import java.util.UUID;

import static org.dependencytrack.workflow.serialization.Serdes.voidSerde;

public class MirrorVulnSourcesWorkflowRunner implements WorkflowRunner<Void, Void> {

    public static final UUID UNIQUE_KEY = UUID.fromString("7c078ec3-cd93-4b84-ba47-1854fe9da0e4");

    @Override
    public Optional<Void> run(final WorkflowRunContext<Void> ctx) throws Exception {
        ctx.callLocalActivity("trigger-nist-mirror", "1", null, voidSerde(), voidSerde(), ignored -> {
            new NistMirrorTask().inform(new NistMirrorEvent());
            return null;
        });

        // TODO: Wait for NIST mirroring to complete.

        ctx.callLocalActivity("trigger-epss-mirror", "1", null, voidSerde(), voidSerde(), ignored -> {
            new EpssMirrorTask().inform(new EpssMirrorEvent());
            return null;
        });

        // TODO: Wait for EPSS mirroring to complete.

        return Optional.empty();
    }

}
