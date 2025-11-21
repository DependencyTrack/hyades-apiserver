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
package org.dependencytrack.dex.engine;

import io.micrometer.core.instrument.Tag;
import org.dependencytrack.dex.proto.event.v1.Event;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

record WorkflowTask(
        UUID workflowRunId,
        String workflowName,
        int workflowVersion,
        String queueName,
        @Nullable String concurrencyGroupId,
        int priority,
        @Nullable Map<String, String> labels,
        int attempt,
        List<Event> history,
        List<Event> inbox) implements Task {

    @Override
    public Set<Tag> meterTags() {
        return Set.of(
                Tag.of("workflowName", workflowName),
                Tag.of("workflowVersion", String.valueOf(workflowVersion)));
    }

}
