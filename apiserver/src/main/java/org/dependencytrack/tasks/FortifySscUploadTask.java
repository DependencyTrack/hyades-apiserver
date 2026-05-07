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
import org.dependencytrack.event.FortifySscUploadEventAbstract;
import org.dependencytrack.integrations.fortifyssc.FortifySscUploader;
import org.dependencytrack.secret.management.SecretManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.http.HttpClient;

public class FortifySscUploadTask extends VulnerabilityManagementUploadTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(FortifySscUploadTask.class);

    private final HttpClient httpClient;
    private final SecretManager secretManager;

    public FortifySscUploadTask(HttpClient httpClient, SecretManager secretManager) {
        this.httpClient = httpClient;
        this.secretManager = secretManager;
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof FortifySscUploadEventAbstract) {
            final FortifySscUploadEventAbstract event = (FortifySscUploadEventAbstract) e;
            LOGGER.debug("Starting Fortify Software Security Center upload task");
            super.inform(event, new FortifySscUploader(httpClient, secretManager));
            LOGGER.debug("Fortify Software Security Center upload complete");
        }
    }
}
