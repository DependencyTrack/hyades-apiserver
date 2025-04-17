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
package org.dependencytrack.persistence.migration.change.v560;

import liquibase.change.custom.CustomSqlChange;
import liquibase.database.Database;
import liquibase.database.jvm.JdbcConnection;
import liquibase.exception.CustomChangeException;
import liquibase.exception.SetupException;
import liquibase.exception.ValidationErrors;
import liquibase.resource.ResourceAccessor;
import liquibase.statement.SqlStatement;
import liquibase.statement.core.UpdateStatement;
import liquibase.structure.core.Column;
import liquibase.structure.core.Table;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

public class ApiKeyMigrationChange implements CustomSqlChange {

    private int apiKeysMigrated = 0;

    @Override
    public SqlStatement[] generateStatements(final Database database) throws CustomChangeException {
        final Connection connection = ((JdbcConnection) database.getConnection()).getWrappedConnection();

        try {
            if (!shouldExecute(connection)) {
                return null;
            }
        } catch (SQLException e) {
            throw new CustomChangeException("Failed to determine whether change should execute", e);
        }

        final List<ApiKey> apiKeys;
        try {
            apiKeys = getApiKeys(connection);
        } catch (SQLException e) {
            throw new CustomChangeException("Failed to retrieve existing API keys", e);
        }

        if (apiKeys.isEmpty()) {
            return null;
        }

        final var migrationStatements = new ArrayList<SqlStatement>(apiKeys.size());
        for (final ApiKey apiKey : apiKeys) {
            final NewApiKey newApiKey;
            try {
                newApiKey = convertApiKey(apiKey.apiKey());
            } catch (RuntimeException e) {
                throw new CustomChangeException("Failed to convert API key with ID " + apiKey.id(), e);
            }

            // Perform some sanity checks and fail the migration if anything looks odd.
            // Best to fail the migration entirely than to mess up any API keys.
            if (newApiKey.secretHash() == null) {
                throw new CustomChangeException("""
                        Unable to migrate API key with ID %d: No secret hash generated \
                        during conversion.""".formatted(apiKey.id()));
            }
            if (newApiKey.publicId() == null) {
                throw new CustomChangeException("""
                        Unable to migrate API key with ID %d: No public ID determined \
                        during conversion.""".formatted(apiKey.id()));
            }

            migrationStatements.add(
                    new UpdateStatement(null, null, database.correctObjectName("APIKEY", Table.class))
                            .addNewColumnValue(database.correctObjectName("SECRET_HASH", Column.class), newApiKey.secretHash())
                            .addNewColumnValue(database.correctObjectName("PUBLIC_ID", Column.class), newApiKey.publicId())
                            .addNewColumnValue(database.correctObjectName("IS_LEGACY", Column.class), true)
                            .setWhereClause("\"ID\" = ?")
                            .addWhereParameter(apiKey.id()));
        }

        apiKeysMigrated = migrationStatements.size();
        return migrationStatements.toArray(new SqlStatement[0]);
    }

    @Override
    public String getConfirmationMessage() {
        if (apiKeysMigrated == 0) {
            return "No API keys to migrate";
        }

        return "Migrated %d API key(s)".formatted(apiKeysMigrated);
    }

    @Override
    public void setUp() throws SetupException {
    }

    @Override
    public void setFileOpener(final ResourceAccessor resourceAccessor) {
    }

    @Override
    public ValidationErrors validate(final Database database) {
        return null;
    }

    private record ApiKey(long id, String apiKey) {
    }

    private boolean shouldExecute(final Connection connection) throws SQLException {
        // When generating a SQL update script against an empty database,
        // the APIKEY table does not yet exist when this change is being invoked.
        try (final ResultSet rs = connection.getMetaData().getTables(null, null, "APIKEY", null)) {
            return rs.next();
        }
    }

    private List<ApiKey> getApiKeys(final Connection connection) throws SQLException {
        final var legacyApiKeys = new ArrayList<ApiKey>();
        try (final PreparedStatement ps = connection.prepareStatement("""
                SELECT "ID"
                     , "APIKEY"
                  FROM "APIKEY"
                 ORDER BY "ID"
                """)) {
            final ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                legacyApiKeys.add(new ApiKey(rs.getLong(1), rs.getString(2)));
            }
        }

        return legacyApiKeys;
    }

    private record NewApiKey(String publicId, String secretHash) {
    }

    private static final int PREFIX_LENGTH = 4; // odt_
    private static final int LEGACY_PUBLIC_ID_LENGTH = 5;
    private static final int LEGACY_FULL_KEY_LENGTH = 32;
    private static final int LEGACY_WITH_PREFIX_FULL_KEY_LENGTH = PREFIX_LENGTH + LEGACY_FULL_KEY_LENGTH;

    /**
     * Heavily simplified version of Alpine's API key decoding logic.
     */
    private static NewApiKey convertApiKey(final String apiKeyString) {
        if (apiKeyString.length() == LEGACY_FULL_KEY_LENGTH) {
            final String publicId = apiKeyString.substring(0, 5);
            final String secret = apiKeyString.substring(5);
            return new NewApiKey(publicId, hashSecret(secret));
        } else if (apiKeyString.length() == LEGACY_WITH_PREFIX_FULL_KEY_LENGTH) {
            final String publicId = apiKeyString.substring(PREFIX_LENGTH, PREFIX_LENGTH + LEGACY_PUBLIC_ID_LENGTH);
            final String secret = apiKeyString.substring(PREFIX_LENGTH + LEGACY_PUBLIC_ID_LENGTH);
            return new NewApiKey(publicId, hashSecret(secret));
        }

        throw new IllegalStateException("Unexpected key format");
    }

    private static String hashSecret(final String plainTextSecret) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA3-256");
            final byte[] secretHash = digest.digest(plainTextSecret.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(secretHash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

}
