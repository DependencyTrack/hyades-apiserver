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
package org.dependencytrack.tasks;

import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.model.Epss;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.persistence.jdbi.EpssDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_EPSS_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_EPSS_FEEDS_URL;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.LockProvider.executeWithLock;
import static org.dependencytrack.util.TaskUtil.getLockConfigForTask;

public class EpssMirrorTask implements LoggableSubscriber {

    private static final Logger LOGGER = LoggerFactory.getLogger(EpssMirrorTask.class);
    private static final int BATCH_SIZE = 100;

    public void inform(final Event e) {
        if (!(e instanceof EpssMirrorEvent)) {
            return;
        }

        try {
            executeWithLock(
                    getLockConfigForTask(getClass()),
                    (LockingTaskExecutor.Task) this::informLocked);
        } catch (Throwable ex) {
            LOGGER.error("Failed to acquire lock or execute task", ex);
        }
    }

    private void informLocked() throws IOException {
        final Config config = loadConfig();
        if (!config.isEnabled()) {
            return;
        }

        LOGGER.info("Downloading feed file from {}", config.feedsBaseUrl());
        final Path feedFilePath = downloadFeedFile(config.feedsBaseUrl());

        LOGGER.info("Processing feed file {}", feedFilePath);
        processFeedFile(feedFilePath);
    }

    private Path downloadFeedFile(final String baseUrl) throws IOException {
        final Path tempFile = Files.createTempFile(null, null);

        final var request = new HttpGet("%s/epss_scores-current.csv.gz".formatted(baseUrl));
        try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            if (response.getStatusLine().getStatusCode() != 200) {
                throw new IllegalStateException("Unexpected response code: " + response.getStatusLine().getStatusCode());
            }

            Files.copy(response.getEntity().getContent(), tempFile, StandardCopyOption.REPLACE_EXISTING);
        }

        return tempFile;
    }

    private void processFeedFile(final Path feedFilePath) throws IOException {
        try (final var fileInputStream = Files.newInputStream(feedFilePath, StandardOpenOption.DELETE_ON_CLOSE);
             final var bufferedInputStream = new BufferedInputStream(fileInputStream);
             final var gzipInputStream = new GZIPInputStream(bufferedInputStream);
             final var inputStreamReader = new InputStreamReader(gzipInputStream);
             final var bufferedReader = new BufferedReader(inputStreamReader)) {
            final var recordBatch = new ArrayList<Epss>(BATCH_SIZE);

            String csvLine;
            boolean isFirstLine = true;
            while ((csvLine = bufferedReader.readLine()) != null) {
                if (csvLine.startsWith("#")) {
                    // Skip comments.
                    continue;
                }
                if (isFirstLine) {
                    // First line is headers.
                    isFirstLine = false;
                    continue;
                }

                final Epss record = parseEpssRecord(csvLine);
                recordBatch.add(record);

                if (recordBatch.size() == BATCH_SIZE) {
                    processBatch(recordBatch);
                    recordBatch.clear();
                }
            }

            if (!recordBatch.isEmpty()) {
                processBatch(recordBatch);
                recordBatch.clear();
            }
        }
    }

    private void processBatch(final List<Epss> records) {
        LOGGER.debug("Processing batch of {} records", records.size());

        final int recordsModified = inJdbiTransaction(
                handle -> handle.attach(EpssDao.class).createOrUpdateAll(records));
        LOGGER.debug("Created or updated {} records", recordsModified);
    }

    private static Epss parseEpssRecord(final String csvLine) {
        final String[] columns = csvLine.split(",");
        if (columns.length != 3) {
            throw new IllegalStateException(
                    "Expected 3 columns, but got %d in line: %s".formatted(
                            columns.length, csvLine));
        }

        return new Epss(
                columns[0],
                new BigDecimal(columns[1]),
                new BigDecimal(columns[2]));
    }

    private record Config(boolean isEnabled, String feedsBaseUrl) {
    }

    private static Config loadConfig() {
        return withJdbiHandle(handle -> {
            final var dao = handle.attach(ConfigPropertyDao.class);

            final boolean isEnabled = dao.getOptionalValue(
                    VULNERABILITY_SOURCE_EPSS_ENABLED, Boolean.class).orElse(false);
            final String feedsBaseUrl = dao.getOptionalValue(
                    VULNERABILITY_SOURCE_EPSS_FEEDS_URL, String.class).orElse(null);

            return new Config(isEnabled, feedsBaseUrl);
        });
    }

}