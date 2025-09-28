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
package org.dependencytrack.workflow.engine.api;

import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * @param name      Name of the queue.
 * @param status    Status of the queue.
 * @param depth     Number of items in the queue.
 * @param createdAt When the queue was created.
 * @param updatedAt When the queue was last updated.
 */
public record ActivityTaskQueue(
        String name,
        Status status,
        int depth,
        Instant createdAt,
        @Nullable Instant updatedAt) {

    public enum Status {

        /**
         * The queue is active.
         */
        ACTIVE,

        /**
         * The queue is paused.
         * <p>
         * Paused queues still accept new items, and workers will complete any in-progress tasks.
         * Workers will not dequeue any more tasks until the queue transitions back to the {@link #ACTIVE} status.
         */
        PAUSED

    }

}
