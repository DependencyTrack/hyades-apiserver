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
package org.dependencytrack.workflow.framework.failure;

public final class ActivityFailureException extends WorkflowFailureException {

    private final String activityName;
    private final int activityVersion;

    public ActivityFailureException(final String activityName, final int activityVersion, final Throwable cause) {
        super("Activity %s v%d failed".formatted(activityName, activityVersion), null, cause);
        this.activityName = activityName;
        this.activityVersion = activityVersion;
    }

    public String getActivityName() {
        return activityName;
    }

    public int getActivityVersion() {
        return activityVersion;
    }

}
