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
package org.dependencytrack.workflow.model;

import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.workflow.payload.PayloadConverter;

import java.util.UUID;

public record StartWorkflowOptions(
        String name,
        int version,
        Integer priority,
        UUID uniqueKey,
        WorkflowPayload argument) {

    public StartWorkflowOptions(final String name, final int version) {
        this(name, version, null, null, null);
    }

    public StartWorkflowOptions withPriority(final Integer priority) {
        return new StartWorkflowOptions(this.name, this.version, priority, this.uniqueKey, this.argument);
    }

    public StartWorkflowOptions withUniqueKey(final UUID uniqueKey) {
        return new StartWorkflowOptions(this.name, this.version, this.priority, uniqueKey, this.argument);
    }

    public StartWorkflowOptions withArgument(final WorkflowPayload argument) {
        return new StartWorkflowOptions(this.name, this.version, this.priority, this.uniqueKey, argument);
    }

    public <T> StartWorkflowOptions withArgument(
            final T argument,
            final PayloadConverter<T> argumentConverter) {
        return new StartWorkflowOptions(this.name, this.version, this.priority, this.uniqueKey,
                argumentConverter.convertToPayload(argument).orElse(null));
    }

}
