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
package org.dependencytrack.persistence.jdbi;

import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

/**
 * @since 5.7.0
 */
public interface ExtensionConfigDao {

    @SqlQuery("""
            SELECT EXISTS(
              SELECT 1
                FROM "EXTENSION_RUNTIME_CONFIG"
               WHERE "EXTENSION_POINT" = :extensionPointName
                 AND "EXTENSION" = :extensionName
            )
            """)
    boolean exists(@Bind String extensionPointName, @Bind String extensionName);

    @SqlQuery("""
            SELECT "CONFIG"
              FROM "EXTENSION_RUNTIME_CONFIG"
             WHERE "EXTENSION_POINT" = :extensionPointName
               AND "EXTENSION" = :extensionName
            """)
    String get(@Bind String extensionPointName, @Bind String extensionName);

    @SqlUpdate("""
            INSERT INTO "EXTENSION_RUNTIME_CONFIG" ("EXTENSION_POINT", "EXTENSION", "CONFIG", "CREATED_AT")
            VALUES (:extensionPointName, :extensionName, CAST(:config AS JSONB), NOW())
            ON CONFLICT ("EXTENSION_POINT", "EXTENSION")
            DO UPDATE
            SET "CONFIG" = EXCLUDED."CONFIG"
              , "UPDATED_AT" = NOW()
            WHERE "EXTENSION_RUNTIME_CONFIG"."CONFIG" IS DISTINCT FROM EXCLUDED."CONFIG"
            """)
    boolean save(@Bind String extensionPointName, @Bind String extensionName, @Bind String config);

}
