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
package org.dependencytrack.persistence.migration;

import org.dependencytrack.support.liquibase.MigrationExecutor;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
class PackageMetadataMigrationTest {

    record PackageMetadataRow(String purl, String latestVersion) {
    }

    record ArtifactMetadataRow(
            String purl,
            String packagePurl,
            @Nullable String md5,
            @Nullable String sha1,
            @Nullable String sha256,
            @Nullable String sha512,
            @Nullable Timestamp publishedAt) {
    }

    @Container
    private final PostgreSQLContainer postgresContainer =
            new PostgreSQLContainer(DockerImageName.parse("postgres:14-alpine"))
                    .withCommand("postgres", "-c", "fsync=off", "-c", "full_page_writes=off")
                    .withTmpFs(Map.of("/var/lib/postgresql/data", "rw"));

    @Test
    void shouldMigratePackageMetadata() throws Exception {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());

        final var migrationExecutor = new MigrationExecutor(dataSource, "migration/changelog-main.xml");

        migrationExecutor.executeMigrationToTag("pre-package-metadata-migration");

        final var newerCheck = Timestamp.from(Instant.now().minus(1, ChronoUnit.DAYS));
        final var fetchTime = Timestamp.from(Instant.now().minus(3, ChronoUnit.HOURS));
        final var publishedAt = Timestamp.from(Instant.now().minus(30, ChronoUnit.DAYS));

        try (final Connection connection = dataSource.getConnection()) {
            // Create a project for COMPONENT FK.
            try (final PreparedStatement stmt = connection.prepareStatement("""
                    INSERT INTO "PROJECT" ("ID", "NAME", "UUID")
                    VALUES (1, 'test-project', ?::UUID)
                    """)) {
                stmt.setString(1, UUID.randomUUID().toString());
                stmt.executeUpdate();
            }

            // Scenario 1: Basic match - Maven component with namespace.
            insertComponent(connection, 1, 1, "bar", "com.foo",
                    "pkg:maven/com.foo/bar@1.0", "pkg:maven/com.foo/bar@1.0");
            insertRepoMeta(connection, 1, "MAVEN", "com.foo", "bar", "2.0", newerCheck);

            // Scenario 2: Null namespace - NPM component without group.
            insertComponent(connection, 2, 1, "lodash", null,
                    "pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.21");
            insertRepoMeta(connection, 2, "NPM", null, "lodash", "4.18.0", newerCheck);

            // Scenario 3: Multiple components with same package coordinates - two versions join to
            // the same repo meta row, producing duplicate derived PURLs. DISTINCT ON deduplicates.
            insertComponent(connection, 3, 1, "commons-lang3", "org.apache",
                    "pkg:maven/org.apache/commons-lang3@3.12", "pkg:maven/org.apache/commons-lang3@3.12");
            insertComponent(connection, 4, 1, "commons-lang3", "org.apache",
                    "pkg:maven/org.apache/commons-lang3@3.13", "pkg:maven/org.apache/commons-lang3@3.13");
            insertRepoMeta(connection, 3, "MAVEN", "org.apache", "commons-lang3", "3.15", newerCheck);

            // Scenario 4: No matching component - should not be migrated.
            insertRepoMeta(connection, 5, "PYPI", null, "nonexistent-pkg", "1.0", newerCheck);

            // Scenario 5: PURLCOORDINATES without version but with qualifier in coordinates
            // - excluded by the PURL CHECK constraint filter (contains '?').
            insertComponent(connection, 5, 1, "guava", "com.google",
                    "pkg:maven/com.google/guava?type=jar", "pkg:maven/com.google/guava?type=jar");
            insertRepoMeta(connection, 6, "MAVEN", "com.google", "guava", "32.0", newerCheck);

            // Scenario 6: Component with valid PURL for integrity meta migration.
            insertComponent(connection, 6, 1, "jackson-core", "com.fasterxml",
                    "pkg:maven/com.fasterxml/jackson-core@2.15", "pkg:maven/com.fasterxml/jackson-core@2.15");
            insertRepoMeta(connection, 7, "MAVEN", "com.fasterxml", "jackson-core", "2.16", newerCheck);

            // INTEGRITY_META_COMPONENT data.
            // Scenario A: Basic match - has corresponding PACKAGE_METADATA.
            insertIntegrityMeta(connection, 1, "pkg:maven/com.foo/bar@1.0",
                    "d41d8cd98f00b204", "da39a3ee5e6b4b0d", "e3b0c44298fc1c14", "cf83e1357eefb8bd",
                    publishedAt, fetchTime, "PROCESSED");

            // Scenario B: Orphaned - no matching PACKAGE_METADATA row (nonexistent package PURL).
            insertIntegrityMeta(connection, 2, "pkg:pypi/orphaned-pkg@1.0",
                    null, null, null, null,
                    null, fetchTime, "PROCESSED");

            // Scenario C: Null hashes - should be preserved.
            insertIntegrityMeta(connection, 3, "pkg:maven/com.fasterxml/jackson-core@2.15",
                    null, "abc123def456", null, null,
                    publishedAt, fetchTime, "PROCESSED");


        }

        migrationExecutor.executeMigration();

        try (final Connection conn = dataSource.getConnection()) {
            // Verify PACKAGE_METADATA contents.
            final var packageMetadataRows = new ArrayList<PackageMetadataRow>();
            try (final PreparedStatement stmt = conn.prepareStatement("""
                    SELECT "PURL"
                         , "LATEST_VERSION"
                      FROM "PACKAGE_METADATA"
                    """)) {
                final ResultSet rs = stmt.executeQuery();
                while (rs.next()) {
                    packageMetadataRows.add(new PackageMetadataRow(
                            rs.getString("PURL"),
                            rs.getString("LATEST_VERSION")));
                }
            }

            // Scenario 1: Maven with namespace.
            assertThat(packageMetadataRows).anySatisfy(row -> {
                assertThat(row.purl()).isEqualTo("pkg:maven/com.foo/bar");
                assertThat(row.latestVersion()).isEqualTo("2.0");
            });

            // Scenario 2: NPM without namespace.
            assertThat(packageMetadataRows).anySatisfy(row -> {
                assertThat(row.purl()).isEqualTo("pkg:npm/lodash");
                assertThat(row.latestVersion()).isEqualTo("4.18.0");
            });

            // Scenario 3: Deduplicated - single row, most recent LAST_CHECK wins (version 3.15).
            assertThat(packageMetadataRows).anySatisfy(row -> {
                assertThat(row.purl()).isEqualTo("pkg:maven/org.apache/commons-lang3");
                assertThat(row.latestVersion()).isEqualTo("3.15");
            });

            // Scenario 4: No matching component - not present.
            assertThat(packageMetadataRows).noneSatisfy(row ->
                    assertThat(row.purl()).isEqualTo("pkg:pypi/nonexistent-pkg"));

            // Scenario 5: PURL with qualifiers - excluded.
            assertThat(packageMetadataRows).noneSatisfy(row ->
                    assertThat(row.purl()).startsWith("pkg:maven/com.google/guava"));

            // Scenario 6: jackson-core should be present.
            assertThat(packageMetadataRows).anySatisfy(row -> {
                assertThat(row.purl()).isEqualTo("pkg:maven/com.fasterxml/jackson-core");
                assertThat(row.latestVersion()).isEqualTo("2.16");
            });

            // Total: scenarios 1, 2, 3, 6 = 4 rows.
            assertThat(packageMetadataRows).hasSize(4);

            // Verify PACKAGE_ARTIFACT_METADATA contents.
            final var artifactMetadataRows = new ArrayList<ArtifactMetadataRow>();
            try (final PreparedStatement stmt = conn.prepareStatement("""
                    SELECT "PURL"
                         , "PACKAGE_PURL"
                         , "HASH_MD5"
                         , "HASH_SHA1"
                         , "HASH_SHA256"
                         , "HASH_SHA512"
                         , "PUBLISHED_AT"
                      FROM "PACKAGE_ARTIFACT_METADATA"
                    """)) {
                final ResultSet rs = stmt.executeQuery();
                while (rs.next()) {
                    artifactMetadataRows.add(new ArtifactMetadataRow(
                            rs.getString("PURL"),
                            rs.getString("PACKAGE_PURL"),
                            rs.getString("HASH_MD5"),
                            rs.getString("HASH_SHA1"),
                            rs.getString("HASH_SHA256"),
                            rs.getString("HASH_SHA512"),
                            rs.getTimestamp("PUBLISHED_AT")));
                }
            }

            // Scenario A: Basic match migrated.
            assertThat(artifactMetadataRows).anySatisfy(row -> {
                assertThat(row.purl()).isEqualTo("pkg:maven/com.foo/bar@1.0");
                assertThat(row.packagePurl()).isEqualTo("pkg:maven/com.foo/bar");
                assertThat(row.md5()).isEqualTo("d41d8cd98f00b204");
                assertThat(row.sha1()).isEqualTo("da39a3ee5e6b4b0d");
                assertThat(row.sha256()).isEqualTo("e3b0c44298fc1c14");
                assertThat(row.sha512()).isEqualTo("cf83e1357eefb8bd");
                assertThat(row.publishedAt()).isNotNull();
            });

            // Scenario B: Orphaned - deleted by cleanup.
            assertThat(artifactMetadataRows).noneSatisfy(row ->
                    assertThat(row.purl()).isEqualTo("pkg:pypi/orphaned-pkg@1.0"));

            // Scenario C: Null hashes preserved.
            assertThat(artifactMetadataRows).anySatisfy(row -> {
                assertThat(row.purl()).isEqualTo("pkg:maven/com.fasterxml/jackson-core@2.15");
                assertThat(row.packagePurl()).isEqualTo("pkg:maven/com.fasterxml/jackson-core");
                assertThat(row.md5()).isNull();
                assertThat(row.sha1()).isEqualTo("abc123def456");
                assertThat(row.sha256()).isNull();
                assertThat(row.sha512()).isNull();
            });

            // Total: scenarios A and C = 2 rows (B deleted).
            assertThat(artifactMetadataRows).hasSize(2);

            // Verify old tables are dropped.
            for (final String tableName : List.of(
                    "INTEGRITY_ANALYSIS", "INTEGRITY_META_COMPONENT", "REPOSITORY_META_COMPONENT")) {
                try (final PreparedStatement stmt = conn.prepareStatement("""
                        SELECT EXISTS (
                          SELECT 1
                            FROM information_schema.tables
                           WHERE table_name = ?
                        )
                        """)) {
                    stmt.setString(1, tableName);
                    final ResultSet rs = stmt.executeQuery();
                    assertThat(rs.next()).isTrue();
                    assertThat(rs.getBoolean(1))
                            .as("Table %s should no longer exist", tableName)
                            .isFalse();
                }
            }
        }
    }

    private static void insertComponent(
            Connection conn,
            long id,
            long projectId,
            String name,
            String group,
            String purl,
            String purlCoordinates) throws Exception {
        try (final PreparedStatement stmt = conn.prepareStatement("""
                INSERT INTO "COMPONENT" (
                  "ID"
                , "PROJECT_ID"
                , "NAME"
                , "GROUP"
                , "PURL"
                , "PURLCOORDINATES"
                , "UUID"
                )
                VALUES (?, ?, ?, ?, ?, ?, ?::UUID)
                """)) {
            stmt.setLong(1, id);
            stmt.setLong(2, projectId);
            stmt.setString(3, name);
            stmt.setString(4, group);
            stmt.setString(5, purl);
            stmt.setString(6, purlCoordinates);
            stmt.setString(7, UUID.randomUUID().toString());
            stmt.executeUpdate();
        }
    }

    private static void insertRepoMeta(
            Connection conn,
            long id,
            String repoType,
            String namespace,
            String name,
            String latestVersion,
            Timestamp lastCheck) throws Exception {
        try (final PreparedStatement stmt = conn.prepareStatement("""
                INSERT INTO "REPOSITORY_META_COMPONENT" (
                  "ID"
                , "REPOSITORY_TYPE"
                , "NAMESPACE"
                , "NAME"
                , "LATEST_VERSION"
                , "LAST_CHECK"
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """)) {
            stmt.setLong(1, id);
            stmt.setString(2, repoType);
            stmt.setString(3, namespace);
            stmt.setString(4, name);
            stmt.setString(5, latestVersion);
            stmt.setTimestamp(6, lastCheck);
            stmt.executeUpdate();
        }
    }

    private static void insertIntegrityMeta(
            Connection conn,
            long id,
            String purl,
            String md5,
            String sha1,
            String sha256,
            String sha512,
            Timestamp publishedAt,
            Timestamp lastFetch,
            String status) throws Exception {
        try (final PreparedStatement stmt = conn.prepareStatement("""
                INSERT INTO "INTEGRITY_META_COMPONENT" (
                  "ID"
                , "PURL"
                , "MD5"
                , "SHA1"
                , "SHA256"
                , "SHA512"
                , "PUBLISHED_AT"
                , "LAST_FETCH"
                , "STATUS"
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            stmt.setLong(1, id);
            stmt.setString(2, purl);
            stmt.setString(3, md5);
            stmt.setString(4, sha1);
            stmt.setString(5, sha256);
            stmt.setString(6, sha512);
            stmt.setTimestamp(7, publishedAt);
            stmt.setTimestamp(8, lastFetch);
            stmt.setString(9, status);
            stmt.executeUpdate();
        }
    }

}
