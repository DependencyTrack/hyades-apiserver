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
package org.dependencytrack.secret.management.database;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Set;
import java.util.concurrent.Callable;

/**
 * @since 5.7.0
 */
final class Crypto {

    private static final long ADVISORY_LOCK_ID = 5320496565362892580L;

    static {
        try {
            AeadConfig.register();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private final DataSource dataSource;
    private final Aead kek;

    Crypto(
            final DataSource dataSource,
            final DatabaseSecretManagerConfig config) {
        this.dataSource = dataSource;
        this.kek = loadKek(config);
    }

    String decrypt(final byte[] cipherText, final byte[] serializedDek) throws GeneralSecurityException {
        // Parse and decrypt the DEK with the KEK.
        final KeysetHandle dekKeysetHandle =
                TinkProtoKeysetFormat.parseEncryptedKeyset(
                        serializedDek, kek, new byte[0]);

        // Decrypt cipher text with the DEK.
        final Aead dek = dekKeysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
        return new String(dek.decrypt(cipherText, new byte[0]), StandardCharsets.UTF_8);
    }

    record EncryptionResult(byte[] cipherText, byte[] serializedDek) {
    }

    EncryptionResult encrypt(final String plainText) throws GeneralSecurityException {
        // Generate a new DEK.
        final KeysetHandle dekHandle = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
        final Aead dek = dekHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);

        // Encrypt plain text with the new DEK.
        final byte[] cipherText = dek.encrypt(plainText.getBytes(StandardCharsets.UTF_8), new byte[0]);

        // Encrypt the DEK with the KEK and serialize it.
        final byte[] serializedDek =
                TinkProtoKeysetFormat.serializeEncryptedKeyset(
                        dekHandle, kek, new byte[0]);

        return new EncryptionResult(cipherText, serializedDek);
    }

    private Aead loadKek(final DatabaseSecretManagerConfig config) {
        // The KEK is usually meant to be fetched from an external KMS.
        // We can't make KMSes a mandatory requirement, hence we support
        // loading the KEK keyset from file instead. However, support for
        // external KMSes would be relatively easy to add if requested.
        // https://developers.google.com/tink/key-management-overview

        return doLocked(() -> {
            // This must execute in a locked context to avoid race conditions
            // when multiple instances start at the same time,
            // and the create-if-missing option is enabled.
            //
            // TODO: Ideally this would be an init task. That requires decoupling
            //  the init task API from the apiserver module first, though.

            final KeysetHandle keysetHandle;
            if (Files.exists(config.getKekKeysetPath())) {
                LoggerFactory.getLogger(DatabaseSecretManager.class).info(
                        "Loading existing KEK keyset from {}", config.getKekKeysetPath());
                keysetHandle =
                        TinkJsonProtoKeysetFormat.parseKeyset(
                                Files.readString(config.getKekKeysetPath()), InsecureSecretKeyAccess.get());
            } else if (config.isCreateKekKeysetIfMissing()) {
                LoggerFactory.getLogger(DatabaseSecretManager.class).info(
                        "KEK keyset at {} does not exist yet; Creating it", config.getKekKeysetPath());
                keysetHandle = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);

                // Ensure all directories leading up to the keyset exist.
                Files.createDirectories(config.getKekKeysetPath().getParent());

                // Create the file with as restrictive permissions as possible.
                // Note that GROUP_READ is necessary for OpenShift deployments,
                // since the user ID is assigned randomly.
                final FileAttribute<?> posixPermissionsAttribute =
                        PosixFilePermissions.asFileAttribute(Set.of(
                                PosixFilePermission.OWNER_READ,
                                PosixFilePermission.OWNER_WRITE,
                                PosixFilePermission.GROUP_READ));

                if (!System.getProperty("os.name").toLowerCase().startsWith("win")) {
                    Files.createFile(config.getKekKeysetPath(), posixPermissionsAttribute);
                } else {
                    // POSIX permissions don't work on Windows.
                    // Note that this fallback is mainly for developers working on Windows
                    // machines, since our official distribution is a Linux-based container image.
                    Files.createFile(config.getKekKeysetPath());
                }

                Files.writeString(
                        config.getKekKeysetPath(),
                        TinkJsonProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get()),
                        StandardOpenOption.WRITE);
            } else {
                throw new IllegalStateException("""
                        KEK keyset at %s does not exist and \
                        dt.secret-management.database.kek-keyset.create-if-missing \
                        is false. Can not continue without a valid KEK keyset.\
                        """.formatted(config.getKekKeysetPath()));
            }

            return keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
        });
    }

    private <T> T doLocked(final Callable<T> callable) {
        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     SELECT pg_advisory_xact_lock(?)
                     """)) {
            ps.setLong(1, ADVISORY_LOCK_ID);
            ps.execute();

            return callable.call();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to acquire advisory lock", e);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

}
