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

import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.BindBean;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlBatch;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * @since 5.6.0
 */
public interface ComponentMetaDao {

    @SqlBatch("""
            INSERT INTO "REPOSITORY_META_COMPONENT"(
              "REPOSITORY_TYPE"
            , "NAMESPACE"
            , "NAME"
            , "LATEST_VERSION"
            , "PUBLISHED"
            , "LAST_CHECK"
            ) VALUES (
              :repositoryType
            , :namespace
            , :name
            , :latestVersion
            , :published
            , :lastCheck
            )
            ON CONFLICT DO NOTHING
            RETURNING "REPOSITORY_TYPE"
                    , "NAMESPACE"
                    , "NAME"
            """)
    @GetGeneratedKeys
    @RegisterConstructorMapper(RepositoryMetaComponent.Identity.class)
    List<RepositoryMetaComponent.Identity> createAllRepositoryMetaComponents(
            @BindBean Collection<RepositoryMetaComponent> metaComponents);

    @SqlBatch("""
            UPDATE "REPOSITORY_META_COMPONENT"
               SET "LATEST_VERSION" = :latestVersion
                 , "PUBLISHED" = :published
                 , "LAST_CHECK" = :lastCheck
             WHERE "REPOSITORY_TYPE" = :repositoryType
               AND "NAMESPACE" = :namespace
               AND "NAME" = :name
               AND "LAST_CHECK" < :lastCheck
            RETURNING "REPOSITORY_TYPE"
                    , "NAMESPACE"
                    , "NAME"
            """)
    @GetGeneratedKeys
    @RegisterConstructorMapper(RepositoryMetaComponent.Identity.class)
    List<RepositoryMetaComponent.Identity> updateAllRepositoryMetaComponents(
            @BindBean Collection<RepositoryMetaComponent> metaComponents);

    @SqlBatch("""
            INSERT INTO "INTEGRITY_META_COMPONENT"(
              "PURL"
            , "REPOSITORY_URL"
            , "PUBLISHED_AT"
            , "MD5"
            , "SHA1"
            , "SHA256"
            , "SHA512"
            , "STATUS"
            , "LAST_FETCH"
            ) VALUES (
              :purl
            , :repositoryUrl
            , :publishedAt
            , :md5
            , :sha1
            , :sha256
            , :sha512
            , :status
            , :lastFetch
            )
            ON CONFLICT DO NOTHING
            RETURNING "PURL"
            """)
    @GetGeneratedKeys
    List<String> createAllIntegrityMetaComponents(@BindBean Collection<IntegrityMetaComponent> metaComponents);

    @SqlBatch("""
            UPDATE "INTEGRITY_META_COMPONENT"
               SET "REPOSITORY_URL" = :repositoryUrl
                 , "PUBLISHED_AT" = :publishedAt
                 , "MD5" = :md5
                 , "SHA1" = :sha1
                 , "SHA256" = :sha256
                 , "SHA512" = :sha512
                 , "STATUS" = :status
                 , "LAST_FETCH" = :lastFetch
             WHERE "PURL" = :purl
               AND "LAST_FETCH" < :lastFetch
            RETURNING "PURL"
            """)
    @GetGeneratedKeys
    List<String> updateAllIntegrityMetaComponents(@BindBean Collection<IntegrityMetaComponent> metaComponents);

    @SqlUpdate("""
            WITH "CTE_CHANGED_COMPONENT_HASH_MATCH_STATUS" AS (
              SELECT "C"."ID" AS "COMPONENT_ID"
                   , "MATCH_COMPONENT_HASH"("C"."MD5", "IMC"."MD5") AS "MD5_HASH_MATCH_STATUS"
                   , "MATCH_COMPONENT_HASH"("C"."SHA1", "IMC"."SHA1") AS "SHA1_HASH_MATCH_STATUS"
                   , "MATCH_COMPONENT_HASH"("C"."SHA_256", "IMC"."SHA256") AS "SHA256_HASH_MATCH_STATUS"
                   , "MATCH_COMPONENT_HASH"("C"."SHA3_512", "IMC"."SHA512") AS "SHA512_HASH_MATCH_STATUS"
                FROM "COMPONENT" AS "C"
               INNER JOIN "INTEGRITY_META_COMPONENT" AS "IMC"
                  ON "IMC"."PURL" = "C"."PURL"
                LEFT JOIN "INTEGRITY_ANALYSIS" AS "IA"
                  ON "IA"."COMPONENT_ID" = "C"."ID"
               WHERE "C"."PURL" = ANY(:purls)
                 AND ("MATCH_COMPONENT_HASH"("C"."MD5", "IMC"."MD5") IS DISTINCT FROM "IA"."MD5_HASH_MATCH_STATUS"
                      OR "MATCH_COMPONENT_HASH"("C"."SHA1", "IMC"."SHA1") IS DISTINCT FROM "IA"."SHA1_HASH_MATCH_STATUS"
                      OR "MATCH_COMPONENT_HASH"("C"."SHA_256", "IMC"."SHA256") IS DISTINCT FROM "IA"."SHA256_HASH_MATCH_STATUS"
                      OR "MATCH_COMPONENT_HASH"("C"."SHA_512", "IMC"."SHA512") IS DISTINCT FROM "IA"."SHA512_HASH_MATCH_STATUS")
            )
            INSERT INTO "INTEGRITY_ANALYSIS"(
              "COMPONENT_ID"
            , "MD5_HASH_MATCH_STATUS"
            , "SHA1_HASH_MATCH_STATUS"
            , "SHA256_HASH_MATCH_STATUS"
            , "SHA512_HASH_MATCH_STATUS"
            , "INTEGRITY_CHECK_STATUS"
            , "UPDATED_AT"
            )
            SELECT "COMPONENT_ID"
                 , "MD5_HASH_MATCH_STATUS"
                 , "SHA1_HASH_MATCH_STATUS"
                 , "SHA256_HASH_MATCH_STATUS"
                 , "SHA512_HASH_MATCH_STATUS"
                 , "COMPONENT_INTEGRITY_CHECK_STATUS"(
                     "MD5_HASH_MATCH_STATUS"
                   , "SHA1_HASH_MATCH_STATUS"
                   , "SHA256_HASH_MATCH_STATUS"
                   , "SHA512_HASH_MATCH_STATUS"
                   ) AS "INTEGRITY_CHECK_STATUS"
                 , NOW() AS "UPDATED_AT"
              FROM "CTE_CHANGED_COMPONENT_HASH_MATCH_STATUS"
                ON CONFLICT ("COMPONENT_ID") DO UPDATE
               SET "MD5_HASH_MATCH_STATUS" = EXCLUDED."MD5_HASH_MATCH_STATUS"
                 , "SHA1_HASH_MATCH_STATUS" = EXCLUDED."SHA1_HASH_MATCH_STATUS"
                 , "SHA256_HASH_MATCH_STATUS" = EXCLUDED."SHA256_HASH_MATCH_STATUS"
                 , "SHA512_HASH_MATCH_STATUS" = EXCLUDED."SHA512_HASH_MATCH_STATUS"
                 , "INTEGRITY_CHECK_STATUS" = EXCLUDED."INTEGRITY_CHECK_STATUS"
                 , "UPDATED_AT" = EXCLUDED."UPDATED_AT"
            """)
    int createOrUpdateIntegrityAnalysesForPurls(@Bind Collection<String> purls);

    @SqlUpdate("""
            WITH "CTE_CHANGED_COMPONENT_HASH_MATCH_STATUS" AS (
              SELECT "C"."ID" AS "COMPONENT_ID"
                   , "MATCH_COMPONENT_HASH"("C"."MD5", "IMC"."MD5") AS "MD5_HASH_MATCH_STATUS"
                   , "MATCH_COMPONENT_HASH"("C"."SHA1", "IMC"."SHA1") AS "SHA1_HASH_MATCH_STATUS"
                   , "MATCH_COMPONENT_HASH"("C"."SHA_256", "IMC"."SHA256") AS "SHA256_HASH_MATCH_STATUS"
                   , "MATCH_COMPONENT_HASH"("C"."SHA3_512", "IMC"."SHA512") AS "SHA512_HASH_MATCH_STATUS"
                FROM "COMPONENT" AS "C"
               INNER JOIN "INTEGRITY_META_COMPONENT" AS "IMC"
                  ON "IMC"."PURL" = "C"."PURL"
                LEFT JOIN "INTEGRITY_ANALYSIS" AS "IA"
                  ON "IA"."COMPONENT_ID" = "C"."ID"
               WHERE "C"."UUID" = ANY((:uuids)::TEXT[])
                 AND ("MATCH_COMPONENT_HASH"("C"."MD5", "IMC"."MD5") IS DISTINCT FROM "IA"."MD5_HASH_MATCH_STATUS"
                      OR "MATCH_COMPONENT_HASH"("C"."SHA1", "IMC"."SHA1") IS DISTINCT FROM "IA"."SHA1_HASH_MATCH_STATUS"
                      OR "MATCH_COMPONENT_HASH"("C"."SHA_256", "IMC"."SHA256") IS DISTINCT FROM "IA"."SHA256_HASH_MATCH_STATUS"
                      OR "MATCH_COMPONENT_HASH"("C"."SHA_512", "IMC"."SHA512") IS DISTINCT FROM "IA"."SHA512_HASH_MATCH_STATUS")
            )
            INSERT INTO "INTEGRITY_ANALYSIS"(
              "COMPONENT_ID"
            , "MD5_HASH_MATCH_STATUS"
            , "SHA1_HASH_MATCH_STATUS"
            , "SHA256_HASH_MATCH_STATUS"
            , "SHA512_HASH_MATCH_STATUS"
            , "INTEGRITY_CHECK_STATUS"
            , "UPDATED_AT"
            )
            SELECT "COMPONENT_ID"
                 , "MD5_HASH_MATCH_STATUS"
                 , "SHA1_HASH_MATCH_STATUS"
                 , "SHA256_HASH_MATCH_STATUS"
                 , "SHA512_HASH_MATCH_STATUS"
                 , "COMPONENT_INTEGRITY_CHECK_STATUS"(
                     "MD5_HASH_MATCH_STATUS"
                   , "SHA1_HASH_MATCH_STATUS"
                   , "SHA256_HASH_MATCH_STATUS"
                   , "SHA512_HASH_MATCH_STATUS"
                   ) AS "INTEGRITY_CHECK_STATUS"
                 , NOW() AS "UPDATED_AT"
              FROM "CTE_CHANGED_COMPONENT_HASH_MATCH_STATUS"
                ON CONFLICT ("COMPONENT_ID") DO UPDATE
               SET "MD5_HASH_MATCH_STATUS" = EXCLUDED."MD5_HASH_MATCH_STATUS"
                 , "SHA1_HASH_MATCH_STATUS" = EXCLUDED."SHA1_HASH_MATCH_STATUS"
                 , "SHA256_HASH_MATCH_STATUS" = EXCLUDED."SHA256_HASH_MATCH_STATUS"
                 , "SHA512_HASH_MATCH_STATUS" = EXCLUDED."SHA512_HASH_MATCH_STATUS"
                 , "INTEGRITY_CHECK_STATUS" = EXCLUDED."INTEGRITY_CHECK_STATUS"
                 , "UPDATED_AT" = EXCLUDED."UPDATED_AT"
            """)
    int createOrUpdateIntegrityAnalysesForComponents(@Bind Collection<UUID> uuids);

    @SqlUpdate("""
            DELETE
              FROM "INTEGRITY_META_COMPONENT"
             WHERE NOT EXISTS(
               SELECT 1
                 FROM "COMPONENT"
                WHERE "COMPONENT"."PURL" = "INTEGRITY_META_COMPONENT"."PURL")
            """)
    int deleteOrphanIntegrityMetaComponents();

    // TODO: Do a NOT EXISTS query against the COMPONENT table instead.
    //  Requires https://github.com/DependencyTrack/hyades/issues/1465.
    @SqlUpdate("""
            DELETE
              FROM "REPOSITORY_META_COMPONENT"
             WHERE NOW() - "LAST_CHECK" > INTERVAL '30' DAY
            """)
    int deleteOrphanRepositoryMetaComponents();

}
