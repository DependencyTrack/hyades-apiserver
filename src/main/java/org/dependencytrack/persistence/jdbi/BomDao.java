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

import org.jdbi.v3.sqlobject.SingleValue;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Duration;
import java.util.UUID;

/**
 * @since 5.6.0
 */
public interface BomDao {

    @SqlUpdate("""
            INSERT INTO "BOM_UPLOAD" ("TOKEN", "UPLOADED_AT", "BOM")
            VALUES (:token, NOW(), :bomBytes)
                ON CONFLICT ("TOKEN")
                DO UPDATE
               SET "UPLOADED_AT" = NOW()
                 , "BOM" = :bomBytes
            """)
    void createUpload(@Bind UUID token, @Bind byte[] bomBytes);

    @SqlQuery("""
            SELECT "BOM"
              FROM "BOM_UPLOAD"
             WHERE "TOKEN" = :token
            """)
    @SingleValue
    byte[] getUploadByToken(@Bind UUID token);

    @SqlUpdate("""
            DELETE
              FROM "BOM_UPLOAD"
             WHERE "TOKEN" = :token
            """)
    boolean deleteUploadByToken(@Bind UUID token);

    @SqlUpdate("""
            DELETE
              FROM "BOM_UPLOAD"
             WHERE NOW() - "UPLOADED_AT" > :duration
            """)
    int deleteAllUploadsForRetentionDuration(@Bind Duration duration);

}
