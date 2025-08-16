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
package org.dependencytrack.workflow.api.failure;

import org.jspecify.annotations.Nullable;

public final class SideEffectFailureException extends FailureException {

    private final String sideEffectName;

    public SideEffectFailureException(final String sideEffectName, @Nullable final Throwable cause) {
        super("Side effect %s failed".formatted(sideEffectName), null, cause);
        this.sideEffectName = sideEffectName;
    }

    public String getSideEffectName() {
        return sideEffectName;
    }

}
