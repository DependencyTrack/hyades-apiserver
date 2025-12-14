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
import org.jdbi.v3.core.statement.Update;

import java.time.Duration;

import static java.util.Objects.requireNonNull;

public final class LockSupport {

    private LockSupport() {
    }

    public static boolean tryAcquireAdvisoryLock(Handle handle, long lockId) {
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

    public static boolean tryAcquireLease(Handle handle, String name, String instanceId, Duration duration) {
        requireNonNull(handle, "handle must not be null");
        requireNonNull(name, "name must not be null");
        requireNonNull(instanceId, "instanceId must not be null");

        final Query query = handle.createQuery("""
                with cte_acquisition as (
                  insert into dex_lease (name, acquired_by, acquired_at, expires_at)
                  values (:name, :instanceId, now(), now() + :duration)
                  on conflict (name) do update
                  set acquired_by = :instanceId
                    , acquired_at = now()
                    , expires_at = now() + :duration
                  where dex_lease.expires_at <= now()
                  returning acquired_by
                )
                select acquired_by
                  from cte_acquisition
                 union all
                select acquired_by
                  from dex_lease
                 where name = :name
                   and expires_at > now()
                   and not exists(select 1 from cte_acquisition)
                """);

        final String leaseHolder = query
                .bind("name", name)
                .bind("instanceId", instanceId)
                .bind("duration", duration)
                .mapTo(String.class)
                .findOne()
                .orElse(null);

        return instanceId.equals(leaseHolder);
    }

    public static void releaseAllLeases(Handle handle, String instanceId) {
        requireNonNull(handle, "handle must not be null");
        requireNonNull(instanceId, "instanceId must not be null");

        final Update update = handle.createUpdate("""
                delete
                  from dex_lease
                 where acquired_by = :instanceId
                """);

        update.bind("instanceId", instanceId).execute();
    }

}
