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
package org.dependencytrack.plugin;

import org.dependencytrack.plugin.api.storage.CompareAndDeleteResult;
import org.dependencytrack.plugin.api.storage.CompareAndPutResult;
import org.dependencytrack.plugin.api.storage.ExtensionKVStore;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;
import org.jspecify.annotations.NonNull;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_QUERY_NAME;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.7.0
 */
final class DatabaseExtensionKVStore implements ExtensionKVStore {

    private final String extensionPointName;
    private final String extensionName;

    DatabaseExtensionKVStore(
            final @NonNull String extensionPointName,
            final @NonNull String extensionName) {
        this.extensionPointName = requireNonNull(extensionPointName, "extensionPointName must not be null");
        this.extensionName = requireNonNull(extensionName, "extensionName must not be null");

    }

    @Override
    public void putMany(final @NonNull Map<String, String> kvPairs) {
        requireNonNull(kvPairs, "kvPairs must not be null");
        if (kvPairs.isEmpty()) {
            return;
        }

        useJdbiTransaction(handle -> {
            final PreparedBatch preparedBatch = handle.prepareBatch("""
                    INSERT INTO "EXTENSION_KV_STORE" ("EXTENSION_POINT", "EXTENSION", "KEY", "VALUE", "CREATED_AT", "VERSION")
                    VALUES (:extensionPointName, :extensionName, :key, :value, NOW(), 0)
                    ON CONFLICT ("EXTENSION_POINT", "EXTENSION", "KEY")
                    DO UPDATE
                    SET "VALUE" = EXCLUDED."VALUE"
                      , "UPDATED_AT" = NOW()
                      , "VERSION" = "EXTENSION_KV_STORE"."VERSION" + 1
                    WHERE "EXTENSION_KV_STORE"."VALUE" IS DISTINCT FROM EXCLUDED."VALUE"
                    """);

            for (final Map.Entry<String, String> entry : kvPairs.entrySet()) {
                preparedBatch
                        .define(ATTRIBUTE_QUERY_NAME, "%s#putMany".formatted(getClass().getSimpleName()))
                        .bind("extensionPointName", extensionPointName)
                        .bind("extensionName", extensionName)
                        .bind("key", entry.getKey())
                        .bind("value", entry.getValue())
                        .add();
            }

            preparedBatch.execute();
        });
    }

    @Override
    public @NonNull CompareAndPutResult compareAndPut(
            final @NonNull String key,
            final @NonNull String value,
            final Long expectedVersion) {
        if (expectedVersion == null) {
            return compareAndPutCreate(key, value);
        }

        return compareAndPutUpdate(key, value, expectedVersion);
    }

    private @NonNull CompareAndPutResult compareAndPutCreate(final String key, final String value) {
        final Long newVersion = inJdbiTransaction(handle -> {
            final Update update = handle.createUpdate("""
                    INSERT INTO "EXTENSION_KV_STORE" ("EXTENSION_POINT", "EXTENSION", "KEY", "VALUE", "CREATED_AT", "VERSION")
                    VALUES (:extensionPointName, :extensionName, :key, :value, NOW(), 0)
                    ON CONFLICT ("EXTENSION_POINT", "EXTENSION", "KEY") DO NOTHING
                    RETURNING "VERSION"
                    """);

            return update
                    .define(ATTRIBUTE_QUERY_NAME, "%s#compareAndPutCreate".formatted(getClass().getSimpleName()))
                    .bind("extensionPointName", extensionPointName)
                    .bind("extensionName", extensionName)
                    .bind("key", key)
                    .bind("value", value)
                    .executeAndReturnGeneratedKeys()
                    .mapTo(long.class)
                    .findOne()
                    .orElse(null);
        });

        return newVersion != null
                ? new CompareAndPutResult.Success(newVersion)
                : new CompareAndPutResult.Failure(CompareAndPutResult.Failure.Reason.ALREADY_EXISTS);
    }

    private @NonNull CompareAndPutResult compareAndPutUpdate(
            final String key,
            final String value,
            final long expectedVersion) {
        final Long newVersion = inJdbiTransaction(handle -> {
            final Update update = handle.createUpdate("""
                    UPDATE "EXTENSION_KV_STORE"
                       SET "VALUE" = :value
                         , "UPDATED_AT" = NOW()
                         , "VERSION" = "VERSION" + 1
                     WHERE "EXTENSION_POINT" = :extensionPointName
                       AND "EXTENSION" = :extensionName
                       AND "KEY" = :key
                       AND "VERSION" = :expectedVersion
                    RETURNING "VERSION"
                    """);

            return update
                    .define(ATTRIBUTE_QUERY_NAME, "%s#compareAndPutUpdate".formatted(getClass().getSimpleName()))
                    .bind("extensionPointName", extensionPointName)
                    .bind("extensionName", extensionName)
                    .bind("key", key)
                    .bind("value", value)
                    .bind("expectedVersion", expectedVersion)
                    .executeAndReturnGeneratedKeys()
                    .mapTo(long.class)
                    .findOne()
                    .orElse(null);
        });

        return newVersion != null
                ? new CompareAndPutResult.Success(newVersion)
                : new CompareAndPutResult.Failure(CompareAndPutResult.Failure.Reason.VERSION_MISMATCH);
    }

    @Override
    public @NonNull List<Entry> getAll() {
        return withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT "KEY"
                         , "VALUE"
                         , "CREATED_AT"
                         , "UPDATED_AT"
                         , "VERSION"
                      FROM "EXTENSION_KV_STORE"
                     WHERE "EXTENSION_POINT" = :extensionPointName
                       AND "EXTENSION" = :extensionName
                    """);

            return query
                    .define(ATTRIBUTE_QUERY_NAME, "%s#getAll".formatted(getClass().getSimpleName()))
                    .bind("extensionPointName", extensionPointName)
                    .bind("extensionName", extensionName)
                    .map(ConstructorMapper.of(Entry.class))
                    .list();
        });
    }

    @Override
    public @NonNull Map<String, Entry> getMany(final @NonNull Collection<String> keys) {
        requireNonNull(keys, "keys must not be null");
        if (keys.isEmpty()) {
            return Collections.emptyMap();
        }

        return withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT "KEY"
                         , "VALUE"
                         , "CREATED_AT"
                         , "UPDATED_AT"
                         , "VERSION"
                      FROM "EXTENSION_KV_STORE"
                     WHERE "EXTENSION_POINT" = :extensionPointName
                       AND "EXTENSION" = :extensionName
                       AND "KEY" = ANY(:keys)
                    """);

            return query
                    .define(ATTRIBUTE_QUERY_NAME, "%s#getMany".formatted(getClass().getSimpleName()))
                    .bind("extensionPointName", extensionPointName)
                    .bind("extensionName", extensionName)
                    .bindArray("keys", String.class, keys)
                    .map(ConstructorMapper.of(Entry.class))
                    .collectToMap(Entry::key, Function.identity());
        });
    }

    @Override
    public void deleteMany(final @NonNull Collection<String> keys) {
        requireNonNull(keys, "keys must not be null");
        if (keys.isEmpty()) {
            return;
        }

        useJdbiTransaction(handle -> {
            final Update update = handle.createUpdate("""
                    DELETE FROM "EXTENSION_KV_STORE"
                     WHERE "EXTENSION_POINT" = :extensionPointName
                       AND "EXTENSION" = :extensionName
                       AND "KEY" = ANY(:keys)
                    """);

            update
                    .define(ATTRIBUTE_QUERY_NAME, "%s#deleteMany".formatted(getClass().getSimpleName()))
                    .bind("extensionPointName", extensionPointName)
                    .bind("extensionName", extensionName)
                    .bindArray("keys", String.class, keys)
                    .execute();
        });
    }

    @Override
    public @NonNull CompareAndDeleteResult compareAndDelete(
            final @NonNull String key,
            final long expectedVersion) {
        requireNonNull(key, "key must not be null");

        final int modifiedRows = inJdbiTransaction(handle -> {
            final Update update = handle.createUpdate("""
                    DELETE
                      FROM "EXTENSION_KV_STORE"
                     WHERE "EXTENSION_POINT" = :extensionPointName
                       AND "EXTENSION" = :extensionName
                       AND "KEY" = :key
                       AND "VERSION" = :expectedVersion
                    """);

            return update
                    .define(ATTRIBUTE_QUERY_NAME, "%s#compareAndDelete".formatted(getClass().getSimpleName()))
                    .bind("extensionPointName", extensionPointName)
                    .bind("extensionName", extensionName)
                    .bind("key", key)
                    .bind("expectedVersion", expectedVersion)
                    .execute();
        });

        return modifiedRows > 0
                ? new CompareAndDeleteResult.Success()
                : new CompareAndDeleteResult.Failure(CompareAndDeleteResult.Failure.Reason.VERSION_MISMATCH);
    }

}
