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
package org.dependencytrack.dex.engine.support;

import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.Query;

import static java.util.Objects.requireNonNull;

public final class LockSupport {

    private LockSupport() {
    }

    public static boolean tryAcquireAdvisoryLock(final Handle handle, final long lockId) {
        requireNonNull(handle, "handle must not be null");
        if (!handle.isInTransaction()) {
            throw new IllegalStateException("Not in a database transaction");
        }

        final Query query = handle.createQuery("""
                select pg_try_advisory_xact_lock(:lockId)
                """);

        return query
                .bind("lockId", lockId)
                .mapTo(boolean.class)
                .one();
    }

}
