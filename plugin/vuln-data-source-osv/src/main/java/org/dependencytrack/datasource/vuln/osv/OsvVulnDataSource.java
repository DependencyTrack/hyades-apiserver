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
package org.dependencytrack.datasource.vuln.osv;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.util.Timestamps;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.dependencytrack.datasource.vuln.osv.schema.OsvSchema;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static java.util.Objects.requireNonNull;
import static java.util.function.Predicate.not;
import static org.dependencytrack.datasource.vuln.osv.CycloneDxPropertyNames.PROPERTY_OSV_ECOSYSTEM;

/**
 * @since 5.7.0
 */
final class OsvVulnDataSource implements VulnDataSource {

    private static final Logger LOGGER = LoggerFactory.getLogger(OsvVulnDataSource.class);

    private final WatermarkManager watermarkManager;
    private final ObjectMapper objectMapper;
    private final URL dataUrl;
    private final List<String> ecosystems;
    private final Set<String> successfullyCompletedEcosystems;
    private final HttpClient httpClient;
    private String currentEcosystem;
    private int currentEcosystemIndex;
    private Path currentEcosystemDirPath;
    private Stream<Path> currentEcosystemFileStream;
    private Iterator<Path> currentEcosystemFileIterator;
    private boolean hasNextCalled;
    private Bom nextItem;
    private final boolean isAliasSyncEnabled;

    OsvVulnDataSource(
            final WatermarkManager watermarkManager,
            final ObjectMapper objectMapper,
            final URL dataUrl,
            final List<String> ecosystems,
            final boolean isAliasSyncEnabled) {
        this.watermarkManager = watermarkManager;
        this.objectMapper = objectMapper;
        this.dataUrl = dataUrl;
        this.ecosystems = ecosystems;
        this.isAliasSyncEnabled = isAliasSyncEnabled;
        this.successfullyCompletedEcosystems = new HashSet<>();
        this.httpClient = HttpClient.newHttpClient();
    }

    @Override
    public boolean hasNext() {
        if (hasNextCalled && nextItem != null) {
            return true;
        }

        hasNextCalled = true;

        if (currentEcosystemFileIterator != null) {
            final Bom item = readNextItem();
            if (item != null) {
                nextItem = item;
                return true;
            }

            successfullyCompletedEcosystems.add(currentEcosystem);
            closeCurrentEcosystem();
            currentEcosystemIndex++;
        }

        if (currentEcosystemIndex < ecosystems.size()) {
            final boolean nextEcosystemOpened = openNextEcosystem();
            if (nextEcosystemOpened) {
                final Bom item = readNextItem();
                if (item != null) {
                    nextItem = item;
                    return true;
                }
                successfullyCompletedEcosystems.add(currentEcosystem);
                closeCurrentEcosystem();
            }
            currentEcosystemIndex++;
        }

        nextItem = null;
        return false;
    }

    @Override
    public Bom next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }

        final Bom item = nextItem;
        nextItem = null;
        hasNextCalled = false;
        return item;
    }

    @Override
    public void markProcessed(final Bom bov) {
        requireNonNull(bov, "bov must not be null");

        if (bov.getVulnerabilitiesCount() != 1) {
            throw new IllegalArgumentException(
                    "BOV must have exactly one vulnerability, but has "
                            + bov.getVulnerabilitiesCount());
        }

        final Vulnerability vuln = bov.getVulnerabilities(0);

        final String ecosystem = extractEcosystem(vuln);
        if (ecosystem == null) {
            throw new IllegalArgumentException();
        }

        final Instant updatedAt = vuln.hasUpdated()
                ? Instant.ofEpochMilli(Timestamps.toMillis(vuln.getUpdated()))
                : null;
        if (updatedAt == null) {
            throw new IllegalArgumentException();
        }

        watermarkManager.maybeAdvance(ecosystem, updatedAt);
    }

    @Override
    public void close() {
        watermarkManager.maybeCommit(successfullyCompletedEcosystems);
        closeCurrentEcosystem();
        httpClient.close();
    }

    private Bom readNextItem() {
        if (currentEcosystemFileIterator == null || !currentEcosystemFileIterator.hasNext()) {
            return null;
        }

        final Path filePath = currentEcosystemFileIterator.next();
        final OsvSchema schemaInput;
        try {
            schemaInput = objectMapper.readValue(filePath.toFile(), OsvSchema.class);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read OSV advisory", e);
        }

        return ModelConverter.convert(schemaInput, isAliasSyncEnabled);
    }

    private boolean openNextEcosystem() {
        if (currentEcosystemIndex >= ecosystems.size()) {
            return false;
        }

        currentEcosystem = ecosystems.get(currentEcosystemIndex);
        LOGGER.info("Opening ecosystem {}", currentEcosystem);

        currentEcosystemDirPath = downloadEcosystemFiles(currentEcosystem);
        try {
            currentEcosystemFileStream = Files.walk(currentEcosystemDirPath)
                    .filter(not(Files::isDirectory))
                    .filter(file -> file.getFileName().toString().endsWith(".json"));
            currentEcosystemFileIterator = currentEcosystemFileStream.iterator();
        } catch (IOException e) {
            closeCurrentEcosystem();
            throw new UncheckedIOException("Failed to walk " + currentEcosystemDirPath, e);
        }

        return true;
    }

    private Path downloadEcosystemFiles(final String ecosystem) {
        final Path tempDirPath;
        try {
            tempDirPath = Files.createTempDirectory(null);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to create temp directory", e);
        }

        final Instant watermark = watermarkManager.getWatermark(ecosystem);
        if (watermark == null) {
            LOGGER.debug("No watermark found; Downloading all advisories");
            downloadEcosystemFilesAll(ecosystem, tempDirPath);
        } else {
            LOGGER.debug("Downloading advisories changed since {}", watermark);
            downloadEcosystemFilesIncremental(ecosystem, watermark, tempDirPath);
        }

        return tempDirPath;
    }

    private void downloadEcosystemFilesAll(final String ecosystem, final Path destDirPath) {
        final var request = HttpRequest.newBuilder()
                .uri(URI.create("%s/%s/all.zip".formatted(dataUrl, ecosystem)))
                .build();

        final HttpResponse<InputStream> response;
        try {
            response = httpClient.send(request, BodyHandlers.buffering(BodyHandlers.ofInputStream(), 1024));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to download advisory archive", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while downloading advisory archive", e);
        }

        try (final InputStream responseBodyInputStream = response.body();
             final var zipInputStream = new ZipInputStream(responseBodyInputStream)) {
            ZipEntry zipEntry;
            while ((zipEntry = zipInputStream.getNextEntry()) != null) {
                if (zipEntry.isDirectory()) {
                    LOGGER.debug("Skipping directory {}", zipEntry.getName());
                    continue;
                }

                final Path filePath = destDirPath.resolve(zipEntry.getName());
                if (!filePath.normalize().startsWith(destDirPath.normalize())) {
                    LOGGER.warn("Entry path {} resolves to a location outside of the destination directory; Skipping", filePath);
                    continue;
                }

                LOGGER.debug("Extracting {} to {}", zipEntry.getName(), filePath);
                Files.copy(zipInputStream, filePath);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read advisory archive", e);
        }
    }

    private void downloadEcosystemFilesIncremental(
            final String ecosystem,
            final Instant watermark,
            final Path destDirPath) {
        final Set<String> modifiedIds = getModifiedIds(ecosystem, watermark);
        if (modifiedIds.isEmpty()) {
            LOGGER.info("No new or updated advisories since {}", watermark);
            return;
        }

        // TODO: Use structured concurrency after Java 25 upgrade (https://openjdk.org/jeps/505).
        LOGGER.info("Downloading {} new or updated advisories", modifiedIds.size());
        for (final String modifiedId : modifiedIds) {
            LOGGER.debug("Downloading advisory {}", modifiedId);
            downloadAdvisoryFile(ecosystem, modifiedId, destDirPath);
        }
    }

    private void downloadAdvisoryFile(final String ecosystem, final String advisoryId, final Path destDirPath) {
        final var request = HttpRequest.newBuilder()
                .uri(URI.create("%s/%s/%s.json".formatted(dataUrl, ecosystem, advisoryId)))
                .GET()
                .build();

        final HttpResponse<?> response;
        try {
            response = httpClient.send(request, BodyHandlers.ofFile(destDirPath.resolve("%s.json".formatted(advisoryId))));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to download advisory", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while downloading advisory", e);
        }
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Unexpected response code: " + response.statusCode());
        }
    }

    private void closeCurrentEcosystem() {
        if (currentEcosystemFileStream != null) {
            currentEcosystemFileStream.close();
            currentEcosystemFileIterator = null;
        }

        if (currentEcosystemDirPath != null) {
            try {
                deleteRecursively(currentEcosystemDirPath);
            } catch (IOException e) {
                LOGGER.warn("Failed to delete directory {}", currentEcosystemDirPath, e);
            }
            currentEcosystemDirPath = null;
        }

        currentEcosystem = null;
    }

    private Set<String> getModifiedIds(final String ecosystem, final Instant watermark) {
        final var request = HttpRequest.newBuilder()
                .uri(URI.create("%s/%s/modified_id.csv".formatted(dataUrl, ecosystem)))
                .GET()
                .build();

        final HttpResponse<InputStream> response;
        try {
            response = httpClient.send(request, BodyHandlers.buffering(
                    BodyHandlers.ofInputStream(), 1024));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to download modified IDs", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while downloading modified IDs", e);
        }
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Unexpected response code: " + response.statusCode());
        }

        final var modifiedIds = new HashSet<String>();
        try (final InputStream inputStream = response.body();
             final var inputStreamReader = new InputStreamReader(inputStream);
             final var bufferedReader = new BufferedReader(inputStreamReader)) {
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                final String[] parts = line.split(",", 2);
                if (parts.length != 2) {
                    throw new IllegalStateException();
                }

                final Instant timestamp = Instant.parse(parts[0]);
                if (timestamp.isAfter(watermark)) {
                    modifiedIds.add(parts[1]);
                } else {
                    break;
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        return modifiedIds;
    }

    private static String extractEcosystem(final Vulnerability vuln) {
        for (final Property property : vuln.getPropertiesList()) {
            if (PROPERTY_OSV_ECOSYSTEM.equals(property.getName())) {
                return property.getValue();
            }
        }

        return null;
    }

    private static void deleteRecursively(final Path path) throws IOException {
        try (final Stream<Path> filePaths = Files.walk(path)) {
            filePaths
                    .sorted(Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(File::delete);
        }
    }

}