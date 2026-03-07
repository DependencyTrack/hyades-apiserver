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
package org.dependencytrack.integrations.kenna;

import alpine.common.logging.Logger;
import alpine.model.ConfigProperty;
import alpine.security.crypto.DataEncryption;
import com.fasterxml.jackson.databind.JsonNode;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.common.MultipartBodyPublisher;
import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.integrations.PortfolioFindingUploader;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_CONNECTOR_ID;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_TOKEN;

public class KennaSecurityUploader extends AbstractIntegrationPoint implements PortfolioFindingUploader {

    private static final Logger LOGGER = Logger.getLogger(KennaSecurityUploader.class);
    private static final String ASSET_EXTID_PROPERTY = "kenna.asset.external_id";
    private static final String API_ROOT = "https://api.kennasecurity.com";
    private static final String CONNECTOR_UPLOAD_URL = API_ROOT + "/connectors/%s/data_file";

    private final HttpClient httpClient;
    private String connectorId;

    public KennaSecurityUploader(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String name() {
        return "Kenna Security";
    }

    @Override
    public String description() {
        return "Pushes Dependency-Track findings to Kenna Security";
    }

    @Override
    public boolean isEnabled() {
        final ConfigProperty enabled = qm.getConfigProperty(KENNA_ENABLED.getGroupName(), KENNA_ENABLED.getPropertyName());
        final ConfigProperty connector = qm.getConfigProperty(KENNA_CONNECTOR_ID.getGroupName(), KENNA_CONNECTOR_ID.getPropertyName());
        if (enabled != null && Boolean.valueOf(enabled.getPropertyValue()) && connector != null && connector.getPropertyValue() != null) {
            connectorId = connector.getPropertyValue();
            return true;
        }
        return false;
    }

    @Override
    public InputStream process() {
        LOGGER.debug("Processing...");
        final KennaDataTransformer kdi = new KennaDataTransformer(qm);
        for (final Project project : qm.getAllProjects()) {
            final ProjectProperty externalId = qm.getProjectProperty(project, KENNA_ENABLED.getGroupName(), ASSET_EXTID_PROPERTY);
            if (externalId != null && externalId.getPropertyValue() != null) {
                LOGGER.debug("Transforming findings for project: " + project.getUuid() + " to KDI format");
                kdi.process(project, externalId.getPropertyValue());
            }
        }
        return new ByteArrayInputStream(kdi.generate().toString().getBytes());
    }

    @Override
    public void upload(final InputStream payload) {
        LOGGER.debug("Uploading payload to KennaSecurity");
        final ConfigProperty tokenProperty = qm.getConfigProperty(KENNA_TOKEN.getGroupName(), KENNA_TOKEN.getPropertyName());
        try {
            final String token = new DataEncryption().decryptAsString(tokenProperty.getPropertyValue());

            final var multipart = new MultipartBodyPublisher()
                    .addFormField("run", "true")
                    .addFilePart("file", "findings.json", payload, "application/json");

            final var request = HttpRequest.newBuilder()
                    .uri(URI.create(String.format(CONNECTOR_UPLOAD_URL, connectorId)))
                    .header("X-Risk-Token", token)
                    .header("Accept", "application/json")
                    .header("Content-Type", multipart.contentType())
                    .POST(multipart.build())
                    .build();

            final HttpResponse<String> response = httpClient
                    .send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200 && response.body() != null) {
                final JsonNode root = Mappers.jsonMapper().readTree(response.body());
                if ("true".equals(root.path("success").asText())) {
                    LOGGER.debug("Successfully uploaded KDI");
                    return;
                }
                LOGGER.warn("An unexpected response was received uploading findings to Kenna Security");
            } else {
                handleUnexpectedHttpResponse(LOGGER, request.uri().toString(), response.statusCode(), response.body());
            }
        } catch (Exception e) {
            LOGGER.error("An error occurred attempting to upload findings to Kenna Security", e);
        }
    }
}
