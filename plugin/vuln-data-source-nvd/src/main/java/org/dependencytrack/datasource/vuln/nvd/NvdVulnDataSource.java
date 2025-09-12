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
package org.dependencytrack.datasource.vuln.nvd;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.util.Timestamps;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Comparator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.zip.GZIPInputStream;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
final class NvdVulnDataSource implements VulnDataSource {

    private static final Logger LOGGER = LoggerFactory.getLogger(NvdVulnDataSource.class);

    private final WatermarkManager watermarkManager;
    private final URL feedsUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final List<NvdDataFeed> feeds;
    private NvdDataFeed currentFeed;
    private int currentFeedIndex = 0;
    private InputStream currentFileInputStream;
    private JsonParser currentJsonParser;
    private boolean hasNextCalled = false;
    private boolean completedSuccessfully = false;
    private Bom nextItem;

    NvdVulnDataSource(
            final WatermarkManager watermarkManager,
            final ObjectMapper objectMapper,
            final URL feedsUrl) {
        this.watermarkManager = watermarkManager;
        this.objectMapper = objectMapper;
        this.feedsUrl = feedsUrl;
        this.httpClient = HttpClient.newHttpClient();
        this.feeds = IntStream.range(2002, LocalDate.now().getYear() + 1).boxed()
                .sorted(Comparator.reverseOrder()) // Process newer feeds first.
                .map(NvdDataFeed.YearDataFeed::new)
                .collect(Collectors.toList());
        this.feeds.add(new NvdDataFeed.ModifiedDataFeed());
    }

    @Override
    public boolean hasNext() {
        if (hasNextCalled && nextItem != null) {
            return true;
        }

        hasNextCalled = true;

        if (currentJsonParser != null) {
            final Bom item = readNextItem();
            if (item != null) {
                nextItem = item;
                return true;
            }

            closeCurrentFeed();
            currentFeedIndex++;
        }

        if (currentFeedIndex < feeds.size()) {
            final boolean nextFeedOpened = openNextFeed();
            if (nextFeedOpened) {
                final Bom item = readNextItem();
                if (item != null) {
                    nextItem = item;
                    return true;
                }
                closeCurrentFeed();
            }
            currentFeedIndex++;
        }

        completedSuccessfully = true;
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

        // TODO: Require vulnerabilityCount == 1
        final Vulnerability vuln = bov.getVulnerabilities(0);

        final Instant updatedAt = vuln.hasUpdated()
                ? Instant.ofEpochMilli(Timestamps.toMillis(vuln.getUpdated()))
                : null;
        watermarkManager.maybeAdvance(updatedAt);
    }

    @Override
    public void close() {
        if (completedSuccessfully) {
            // Feed file contents are not ordered by modification date.
            // Committing the watermark is only safe when *all* feed files
            // have been successfully processed.
            watermarkManager.maybeCommit();
        }
        httpClient.close();
        closeCurrentFeed();
    }

    private boolean openNextFeed() {
        if (currentFeedIndex >= feeds.size()) {
            return false;
        }

        currentFeed = feeds.get(currentFeedIndex);
        LOGGER.info("Opening {}", currentFeed);
        
        final NvdDataFeedMetadata feedMetadata = retrieveFeedMetadata(currentFeed);
        if (watermarkManager.getWatermark() != null
            && !watermarkManager.getWatermark().isBefore(feedMetadata.lastModifiedAt())) {
            LOGGER.info("Skipping {}: Below watermark", currentFeed);
            currentFeedIndex++;
            return openNextFeed();
        }

        final Path feedFilePath = downloadFeedFile(currentFeed);

        try {
            currentFileInputStream = Files.newInputStream(feedFilePath, StandardOpenOption.DELETE_ON_CLOSE);
            final var bufferedInputStream = new BufferedInputStream(currentFileInputStream);
            final var gzipInputStream = new GZIPInputStream(bufferedInputStream);
            currentJsonParser = objectMapper.createParser(gzipInputStream);

            // Position cursor at first token.
            currentJsonParser.nextToken();

            // Move cursor to the vulnerabilities array.
            JsonToken currentToken;
            while (currentJsonParser.nextToken() != JsonToken.END_OBJECT) {
                String fieldName = currentJsonParser.currentName();
                currentToken = currentJsonParser.nextToken();

                if ("vulnerabilities".equals(fieldName)) {
                    if (currentToken == JsonToken.START_ARRAY) {
                        return true;
                    } else {
                        currentJsonParser.skipChildren();
                    }
                } else {
                    currentJsonParser.skipChildren();
                }
            }
        } catch (IOException e) {
            closeCurrentFeed();
            throw new UncheckedIOException("Failed to open %s".formatted(currentFeed), e);
        }

        return false;
    }

    private Bom readNextItem() {
        if (currentJsonParser == null) {
            return null;
        }

        final Instant watermark = watermarkManager.getWatermark();

        DefCveItem defCveItem = null;
        while (defCveItem == null) {
            try {
                JsonToken token = currentJsonParser.nextToken();
                if (token == JsonToken.END_ARRAY || token == null) {
                    return null; // End of array or end of file
                }

                defCveItem = objectMapper.readValue(currentJsonParser, DefCveItem.class);
                final Instant cveLastModified = defCveItem.getCve().getLastModified().toInstant();

                if (watermark != null && !watermark.isBefore(cveLastModified)) {
                    LOGGER.debug("Skipping CVE {}: Below watermark", defCveItem.getCve().getId());
                    defCveItem = null;
                }
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to parse CVE", e);
            }
        }

        return ModelConverter.convert(defCveItem);
    }

    private void closeCurrentFeed() {
        try {
            if (currentJsonParser != null) {
                currentJsonParser.close();
                currentJsonParser = null;
            }
            if (currentFileInputStream != null) {
                currentFileInputStream.close();
                currentFileInputStream = null;
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to close current feed", e);
        }

        currentFeed = null;
    }

    private NvdDataFeedMetadata retrieveFeedMetadata(final NvdDataFeed feed) {
        final var feedMetadataUri = URI.create(
                "%s/json/cve/2.0/nvdcve-2.0-%s.meta".formatted(
                        feedsUrl,
                        switch (feed) {
                            case NvdDataFeed.ModifiedDataFeed ignored -> "modified";
                            case NvdDataFeed.YearDataFeed it -> String.valueOf(it.year());
                        }));

        final HttpRequest request = HttpRequest.newBuilder()
                .uri(feedMetadataUri)
                .GET()
                .build();

        final HttpResponse<String> response;
        try {
            response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Failed to retrieve feed metadata from " + feedMetadataUri, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(
                    "Interrupted while retrieving feed metadata from " + feedMetadataUri, e);
        }

        if (response.statusCode() != 200) {
            throw new IllegalStateException(
                    "Unexpected response code: " + response.statusCode());
        }

        return NvdDataFeedMetadata.of(response.body());
    }

    private Path downloadFeedFile(final NvdDataFeed feed) {
        final var feedFileUri = URI.create(
                "%s/json/cve/2.0/nvdcve-2.0-%s.json.gz".formatted(
                        feedsUrl,
                        switch (feed) {
                            case NvdDataFeed.ModifiedDataFeed ignored -> "modified";
                            case NvdDataFeed.YearDataFeed it -> String.valueOf(it.year());
                        }));

        final HttpRequest request = HttpRequest.newBuilder()
                .uri(feedFileUri)
                .GET()
                .build();

        final Path tempFile;
        try {
            tempFile = Files.createTempFile(null, null);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to create temp file", e);
        }

        LOGGER.info("Downloading {} to {}", feedFileUri, tempFile);
        final HttpResponse<Path> response;
        try {
            response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofFile(tempFile));
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Failed to download feed file from " + feedFileUri, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(
                    "Interrupted while downloading feed file from " + feedFileUri, e);
        }

        if (response.statusCode() != 200) {
            throw new IllegalStateException(
                    "Unexpected response code: " + response.statusCode());
        }

        return response.body();
    }

}
