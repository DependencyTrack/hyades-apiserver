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
import org.jdbi.v3.sqlobject.customizer.BindBean;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlBatch;

import java.util.List;

/**
 * @since 5.6.0
 */
public interface MetaComponentDao {

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
    List<RepositoryMetaComponent.Identity> createAllRepositoryMetaComponents(@BindBean List<RepositoryMetaComponent> metaComponents);

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
    List<RepositoryMetaComponent.Identity> updateAllRepositoryMetaComponents(@BindBean List<RepositoryMetaComponent> metaComponents);

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
    List<String> createAllIntegrityMetaComponents(@BindBean List<IntegrityMetaComponent> metaComponents);

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
               AND (
                 "REPOSITORY_URL" IS DISTINCT FROM :repositoryUrl
                 OR "PUBLISHED_AT" IS DISTINCT FROM :publishedAt
                 OR "MD5" IS DISTINCT FROM :md5
                 OR "SHA1" IS DISTINCT FROM :sha1
                 OR "SHA256" IS DISTINCT FROM :sha256
                 OR "SHA512" IS DISTINCT FROM :sha512
                 OR "STATUS" IS DISTINCT FROM :status
               )
            RETURNING "PURL"
            """)
    @GetGeneratedKeys
    List<String> updateAllIntegrityMetaComponents(@BindBean List<IntegrityMetaComponent> metaComponents);

}
