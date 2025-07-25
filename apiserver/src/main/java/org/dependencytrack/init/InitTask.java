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
package org.dependencytrack.init;

/**
 * A task to be run on application startup.
 *
 * @since 5.6.0
 */
public interface InitTask {

    int PRIORITY_HIGHEST = 100;
    int PRIORITY_LOWEST = 0;

    /**
     * @return Priority of the task.
     * @see #PRIORITY_HIGHEST
     * @see #PRIORITY_LOWEST
     */
    int priority();

    /**
     * @return Name of the task. Must be globally unique.
     */
    String name();

    /**
     * Execute the task.
     *
     * @param ctx Context in which the task is executed.
     * @throws Exception When the task execution failed.
     */
    void execute(InitTaskContext ctx) throws Exception;

}
