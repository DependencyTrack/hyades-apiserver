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
package org.dependencytrack.integrations.defectdojo;

import alpine.common.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.common.MultipartBodyPublisher;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

public class DefectDojoClient {

    private static final Logger LOGGER = Logger.getLogger(DefectDojoClient.class);
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    private final HttpClient httpClient;
    private final DefectDojoUploader uploader;
    private final URL baseURL;

    public DefectDojoClient(
            HttpClient httpClient,
            DefectDojoUploader uploader,
            URL baseURL) {
        this.httpClient = httpClient;
        this.uploader = uploader;
        this.baseURL = baseURL;
    }

    public void uploadDependencyTrackFindings(final String token, final String engagementId, final InputStream findingsJson, final Boolean verifyFindings) {
        LOGGER.debug("Uploading Dependency-Track findings to DefectDojo");

        final var multipart = new MultipartBodyPublisher()
                .addFilePart("file", "findings.json", findingsJson, "application/octet-stream")
                .addFormField("engagement", engagementId)
                .addFormField("scan_type", "Dependency Track Finding Packaging Format (FPF) Export")
                .addFormField("verified", Boolean.toString(verifyFindings))
                .addFormField("active", "true")
                .addFormField("minimum_severity", "Info")
                .addFormField("close_old_findings", "true")
                .addFormField("push_to_jira", "false")
                .addFormField("scan_date", DATE_FORMAT.format(new Date()));

        final var request = HttpRequest.newBuilder()
                .uri(URI.create(baseURL + "/api/v2/import-scan/"))
                .header("Accept", "application/json")
                .header("Authorization", "Token " + token)
                .header("Content-Type", multipart.contentType())
                .POST(multipart.build())
                .build();

        try {
            final HttpResponse<String> response = httpClient
                    .send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 201) {
                LOGGER.debug("Successfully uploaded findings to DefectDojo");
            } else {
                uploader.handleUnexpectedHttpResponse(LOGGER, request.uri().toString(), response.statusCode(), response.body());
            }
        } catch (IOException ex) {
            uploader.handleException(LOGGER, ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            uploader.handleException(LOGGER, ex);
        }
    }

    public ArrayList<String> getDojoTestIds(final String token, final String eid) {
        LOGGER.debug("Pulling DefectDojo Tests API ...");
        LOGGER.debug("Make the first pagination call");
        try {
            final String url = baseURL + "/api/v2/tests/?limit=100&engagement=" + eid;
            var request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Accept", "application/json")
                    .header("Authorization", "Token " + token)
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient
                    .send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200 && response.body() != null) {
                JSONObject dojoObj = new JSONObject(response.body());
                JSONArray dojoArray = dojoObj.getJSONArray("results");
                ArrayList<String> dojoTests = jsonToList(dojoArray);

                while (StringUtils.isNotBlank(dojoObj.optString("next"))) {
                    final String nextUrl = dojoObj.getString("next");
                    LOGGER.debug("Making the subsequent pagination call on " + nextUrl);
                    request = HttpRequest.newBuilder()
                            .uri(URI.create(nextUrl))
                            .header("Accept", "application/json")
                            .header("Authorization", "Token " + token)
                            .GET()
                            .build();
                    response = httpClient
                            .send(request, HttpResponse.BodyHandlers.ofString());
                    dojoObj = new JSONObject(response.body());
                    dojoArray = dojoObj.optJSONArray("results");
                    if (dojoArray != null) {
                        dojoTests.addAll(jsonToList(dojoArray));
                    }
                }
                LOGGER.debug("Successfully retrieved the test list ");
                return dojoTests;
            } else {
                LOGGER.warn("DefectDojo Client did not receive expected response while attempting to retrieve tests list "
                        + response.statusCode());
            }
        } catch (IOException ex) {
            uploader.handleException(LOGGER, ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            uploader.handleException(LOGGER, ex);
        }
        return new ArrayList<>();
    }

    public String getDojoTestId(final String engagementID, final ArrayList<String> dojoTests) {
        for (final String dojoTestJson : dojoTests) {
            JSONObject dojoTest = new JSONObject(dojoTestJson);
            if (dojoTest.optString("engagement").equals(engagementID) &&
                    dojoTest.optString("scan_type").equals("Dependency Track Finding Packaging Format (FPF) Export")) {
                return dojoTest.optString("id");
            }
        }
        return "";
    }

    public ArrayList<String> jsonToList(final JSONArray jsonArray) {
        ArrayList<String> list = new ArrayList<>();
        if (jsonArray != null) {
            for (int i = 0; i < jsonArray.length(); i++) {
                list.add(jsonArray.get(i).toString());
            }
        }
        return list;
    }

    public void reimportDependencyTrackFindings(final String token, final String engagementId, final InputStream findingsJson, final String testId, final Boolean doNotReactivate, final Boolean verifyFindings) {
        LOGGER.debug("Re-reimport Dependency-Track findings to DefectDojo per Engagement");

        final var multipart = new MultipartBodyPublisher()
                .addFilePart("file", "findings.json", findingsJson, "application/octet-stream")
                .addFormField("engagement", engagementId)
                .addFormField("scan_type", "Dependency Track Finding Packaging Format (FPF) Export")
                .addFormField("verified", Boolean.toString(verifyFindings))
                .addFormField("active", "true")
                .addFormField("minimum_severity", "Info")
                .addFormField("close_old_findings", "true")
                .addFormField("push_to_jira", "false")
                .addFormField("do_not_reactivate", doNotReactivate.toString())
                .addFormField("test", testId)
                .addFormField("scan_date", DATE_FORMAT.format(new Date()));

        final var request = HttpRequest.newBuilder()
                .uri(URI.create(baseURL + "/api/v2/reimport-scan/"))
                .header("Accept", "application/json")
                .header("Authorization", "Token " + token)
                .header("Content-Type", multipart.contentType())
                .POST(multipart.build())
                .build();

        try {
            final HttpResponse<String> response = httpClient
                    .send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 201) {
                LOGGER.debug("Successfully reimport findings to DefectDojo");
            } else {
                uploader.handleUnexpectedHttpResponse(LOGGER, request.uri().toString(), response.statusCode(), response.body());
            }
        } catch (IOException ex) {
            uploader.handleException(LOGGER, ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            uploader.handleException(LOGGER, ex);
        }
    }
}
