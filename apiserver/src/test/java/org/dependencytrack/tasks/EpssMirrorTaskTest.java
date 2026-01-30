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

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.model.Epss;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_EPSS_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_EPSS_FEEDS_URL;

public class EpssMirrorTaskTest extends PersistenceCapableTest {

    @RegisterExtension
    private static final WireMockExtension wireMock =
            WireMockExtension.newInstance()
                    .options(options().dynamicPort())
                    .build();

    @Test
    public void shouldMirrorEpssRecords() throws Exception {
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_EPSS_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_EPSS_ENABLED.getPropertyName(),
                "true",
                VULNERABILITY_SOURCE_EPSS_ENABLED.getPropertyType(),
                VULNERABILITY_SOURCE_EPSS_ENABLED.getDescription());
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getGroupName(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getPropertyName(),
                wireMock.baseUrl(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getPropertyType(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getDescription());

        final var compressedFeedOutputStream = new ByteArrayOutputStream();
        try (final var gzipOutputStream = new GZIPOutputStream(compressedFeedOutputStream)) {
            gzipOutputStream.write(/* language=CSV */ """
                    #model_version:v2025.03.14,score_date:2025-09-24T12:55:00Z
                    cve,epss,percentile
                    CVE-1999-0001,0.01141,0.7769
                    CVE-1999-0002,0.15347,0.94405
                    CVE-1999-0003,0.90362,0.99581\
                    """.getBytes());
        }

        wireMock.stubFor(get(urlPathEqualTo("/epss_scores-current.csv.gz"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(compressedFeedOutputStream.toByteArray())));

        // Create an existing EPSS record for CVE-1999-0001.
        // It must be updated as part of the mirroring operation.
        qm.persist(new Epss("CVE-1999-0001", BigDecimal.ONE, BigDecimal.ZERO));

        new EpssMirrorTask().inform(new EpssMirrorEvent());

        qm.getPersistenceManager().evictAll();
        final List<Epss> epssRecords = qm.getPersistenceManager().newQuery(Epss.class).executeList();

        assertThat(epssRecords).satisfiesExactlyInAnyOrder(
                epssRecord -> {
                    assertThat(epssRecord.getCve()).isEqualTo("CVE-1999-0001");
                    assertThat(epssRecord.getScore()).isEqualByComparingTo("0.01141");
                    assertThat(epssRecord.getPercentile()).isEqualByComparingTo("0.7769");
                },
                epssRecord -> {
                    assertThat(epssRecord.getCve()).isEqualTo("CVE-1999-0002");
                    assertThat(epssRecord.getScore()).isEqualByComparingTo("0.15347");
                    assertThat(epssRecord.getPercentile()).isEqualByComparingTo("0.94405");
                },
                epssRecord -> {
                    assertThat(epssRecord.getCve()).isEqualTo("CVE-1999-0003");
                    assertThat(epssRecord.getScore()).isEqualByComparingTo("0.90362");
                    assertThat(epssRecord.getPercentile()).isEqualByComparingTo("0.99581");
                });
    }

    @Test
    public void shouldFailOnMalformedFeed() throws Exception {
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_EPSS_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_EPSS_ENABLED.getPropertyName(),
                "true",
                VULNERABILITY_SOURCE_EPSS_ENABLED.getPropertyType(),
                VULNERABILITY_SOURCE_EPSS_ENABLED.getDescription());
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getGroupName(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getPropertyName(),
                wireMock.baseUrl(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getPropertyType(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getDescription());

        final var compressedFeedOutputStream = new ByteArrayOutputStream();
        try (final var gzipOutputStream = new GZIPOutputStream(compressedFeedOutputStream)) {
            gzipOutputStream.write(/* language=CSV */ """
                    cve,epss,percentile
                    CVE-1999-0001,0.01141,0.7769,doesNotBelongHere
                    CVE-1999-0002,0.15347,0.94405\
                    """.getBytes());
        }

        wireMock.stubFor(get(urlPathEqualTo("/epss_scores-current.csv.gz"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(compressedFeedOutputStream.toByteArray())));

        new EpssMirrorTask().inform(new EpssMirrorEvent());

        final List<Epss> epssRecords = qm.getPersistenceManager().newQuery(Epss.class).executeList();
        assertThat(epssRecords).isEmpty();
    }

    @Test
    public void shouldNotExecuteWhenDisabled() {
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_EPSS_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_EPSS_ENABLED.getPropertyName(),
                "false",
                VULNERABILITY_SOURCE_EPSS_ENABLED.getPropertyType(),
                VULNERABILITY_SOURCE_EPSS_ENABLED.getDescription());
        qm.createConfigProperty(
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getGroupName(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getPropertyName(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getDefaultPropertyValue(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getPropertyType(),
                VULNERABILITY_SOURCE_EPSS_FEEDS_URL.getDescription());

        new EpssMirrorTask().inform(new EpssMirrorEvent());

        final List<Epss> epssRecords = qm.getPersistenceManager().newQuery(Epss.class).executeList();
        assertThat(epssRecords).isEmpty();
    }

}