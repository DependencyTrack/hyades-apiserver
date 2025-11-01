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
package org.dependencytrack.notification.publishing.webhook;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.assertj.core.api.Assertions;
import org.dependencytrack.notification.api.publishing.MutableNotificationRuleConfig;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.api.publishing.RetryablePublishException;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.publishing.AbstractNotificationPublisherTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.notification.api.TestNotificationFactory.createBomConsumedTestNotification;

class WebhookNotificationPublisherTest extends AbstractNotificationPublisherTest {

    @RegisterExtension
    private static final WireMockExtension WIREMOCK = WireMockExtension.newInstance()
            .options(WireMockConfiguration.wireMockConfig().dynamicPort())
            .build();

    @Override
    protected NotificationPublisherFactory createPublisherFactory() {
        return new WebhookNotificationPublisherFactory();
    }

    @Override
    protected void customizeRuleConfig(final MutableNotificationRuleConfig ruleConfig) {
    }

    @Override
    protected String getDestination() {
        return WIREMOCK.baseUrl();
    }

    @BeforeEach
    @Override
    protected void beforeEach() throws Exception {
        super.beforeEach();

        WIREMOCK.stubFor(post(anyUrl())
                .willReturn(aResponse()
                        .withStatus(200)));
    }

    @Override
    protected void validateBomConsumedNotificationPublish(final Notification ignored) {
        WIREMOCK.verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "notification": {
                            "id": "010ba7f2-ab4a-73b6-a87d-7b9041d17016",
                            "level": "LEVEL_INFORMATIONAL",
                            "scope": "SCOPE_PORTFOLIO",
                            "group": "GROUP_BOM_CONSUMED",
                            "timestamp": "2006-06-06T06:06:06.666Z",
                            "title": "Bill of Materials Consumed",
                            "content": "A CycloneDX BOM was consumed and will be processed",
                            "subject": {
                              "project": {
                                "uuid": "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
                                "name": "projectName",
                                "version": "projectVersion",
                                "description": "projectDescription",
                                "purl": "pkg:maven/org.acme/projectName@projectVersion",
                                "tags": [
                                  "tag1",
                                  "tag2"
                                ],
                                "isActive": true
                              },
                              "bom": {
                                "content": "bomContent",
                                "format": "CycloneDX",
                                "specVersion": "1.5"
                              },
                              "token" : "eef2f6df-f03d-4cd4-954b-6ca1d73538e2"
                            }
                          }
                        }
                        """)));
    }

    @Override
    protected void validateBomProcessingFailedNotificationPublish(final Notification ignored) {
        WIREMOCK.verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "notification": {
                            "id": "010ba7f2-ab4a-73b6-a87d-7b9041d17016",
                            "level": "LEVEL_ERROR",
                            "scope": "SCOPE_PORTFOLIO",
                            "group": "GROUP_BOM_PROCESSING_FAILED",
                            "timestamp": "2006-06-06T06:06:06.666Z",
                            "title" : "Bill of Materials Processing Failed",
                            "content" : "An error occurred while processing a BOM",
                            "subject": {
                              "project": {
                                "uuid": "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
                                "name": "projectName",
                                "version": "projectVersion",
                                "description": "projectDescription",
                                "purl": "pkg:maven/org.acme/projectName@projectVersion",
                                "tags": [
                                  "tag1",
                                  "tag2"
                                ],
                                "isActive": true
                              },
                              "bom": {
                                "content": "bomContent",
                                "format": "CycloneDX",
                                "specVersion": "1.5"
                              },
                              "cause": "cause",
                              "token" : "eef2f6df-f03d-4cd4-954b-6ca1d73538e2"
                            }
                          }
                        }
                        """)));
    }

    @Override
    protected void validateBomValidationFailedNotificationPublish(final Notification ignored) {
        WIREMOCK.verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "notification": {
                            "id": "010ba7f2-ab4a-73b6-a87d-7b9041d17016",
                            "level": "LEVEL_ERROR",
                            "scope": "SCOPE_PORTFOLIO",
                            "group": "GROUP_BOM_VALIDATION_FAILED",
                            "timestamp": "2006-06-06T06:06:06.666Z",
                            "title" : "Bill of Materials Validation Failed",
                            "content" : "An error occurred while validating a BOM",
                            "subject": {
                              "project": {
                                "uuid": "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
                                "name": "projectName",
                                "version": "projectVersion",
                                "description": "projectDescription",
                                "purl": "pkg:maven/org.acme/projectName@projectVersion",
                                "tags": [
                                  "tag1",
                                  "tag2"
                                ],
                                "isActive": true
                              },
                              "bom": {
                                "content": "(Omitted)"
                              },
                              "errors": [
                                "cause 1",
                                "cause 2"
                              ]
                            }
                          }
                        }
                        """)));
    }

    @Override
    protected void validateNewVulnerabilityNotificationPublish(final Notification ignored) {
        WIREMOCK.verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "notification": {
                            "id": "010ba7f2-ab4a-73b6-a87d-7b9041d17016",
                            "level": "LEVEL_INFORMATIONAL",
                            "scope": "SCOPE_PORTFOLIO",
                            "group": "GROUP_NEW_VULNERABILITY",
                            "timestamp": "2006-06-06T06:06:06.666Z",
                            "title" : "New Vulnerability Identified on Project: [projectName : projectVersion]",
                            "content" : "vulnerabilityDescription",
                            "subject": {
                              "component": {
                                "uuid": "94f87321-a5d1-4c2f-b2fe-95165debebc6",
                                "name": "componentName",
                                "version": "componentVersion"
                              },
                              "project": {
                                "uuid": "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
                                "name": "projectName",
                                "version": "projectVersion",
                                "description": "projectDescription",
                                "purl": "pkg:maven/org.acme/projectName@projectVersion",
                                "tags": [
                                  "tag1",
                                  "tag2"
                                ],
                                "isActive": true
                              },
                              "vulnerability": {
                                "uuid": "bccec5d5-ec21-4958-b3e8-22a7a866a05a",
                                "vulnId": "INT-001",
                                "source": "INTERNAL",
                                "aliases": [
                                  {
                                    "vulnId": "OSV-001",
                                    "source": "OSV"
                                  }
                                ],
                                "title": "vulnerabilityTitle",
                                "subtitle": "vulnerabilitySubTitle",
                                "description": "vulnerabilityDescription",
                                "recommendation": "vulnerabilityRecommendation",
                                "cvssv2": 5.5,
                                "cvssv3": 6.6,
                                "owaspRRLikelihood": 1.1,
                                "owaspRRTechnicalImpact": 2.2,
                                "owaspRRBusinessImpact": 3.3,
                                "severity": "MEDIUM",
                                "cwes": [
                                  {
                                    "cweId": 666,
                                    "name": "Operation on Resource in Wrong Phase of Lifetime"
                                  },
                                  {
                                    "cweId": 777,
                                    "name": "Regular Expression without Anchors"
                                  }
                                ]
                              },
                              "affectedProjectsReference": {
                                "apiUri": "/api/v1/vulnerability/source/INTERNAL/vuln/INT-001/projects",
                                "frontendUri": "/vulnerabilities/INTERNAL/INT-001/affectedProjects"
                              },
                              "vulnerabilityAnalysisLevel": "BOM_UPLOAD_ANALYSIS",
                              "affectedProjects": [
                                {
                                  "uuid": "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
                                  "name": "projectName",
                                  "version": "projectVersion",
                                  "description": "projectDescription",
                                  "purl": "pkg:maven/org.acme/projectName@projectVersion",
                                  "tags": [
                                    "tag1",
                                    "tag2"
                                  ],
                                  "isActive": true
                                }
                              ]
                            }
                          }
                        }
                        """)));
    }

    @Override
    protected void validateNewVulnerableDependencyNotificationPublish(final Notification ignored) {
        WIREMOCK.verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "notification": {
                            "id": "010ba7f2-ab4a-73b6-a87d-7b9041d17016",
                            "level": "LEVEL_INFORMATIONAL",
                            "scope": "SCOPE_PORTFOLIO",
                            "group": "GROUP_NEW_VULNERABLE_DEPENDENCY",
                            "timestamp": "2006-06-06T06:06:06.666Z",
                            "title" : "Vulnerable Dependency Introduced on Project: [projectName : projectVersion]",
                            "content" : "A dependency was introduced that contains 1 known vulnerability",
                            "subject": {
                              "component": {
                                "uuid": "94f87321-a5d1-4c2f-b2fe-95165debebc6",
                                "name": "componentName",
                                "version": "componentVersion"
                              },
                              "project": {
                                "uuid": "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
                                "name": "projectName",
                                "version": "projectVersion",
                                "description": "projectDescription",
                                "purl": "pkg:maven/org.acme/projectName@projectVersion",
                                "tags": [
                                  "tag1",
                                  "tag2"
                                ],
                                "isActive": true
                              },
                              "vulnerabilities": [
                                {
                                  "uuid": "bccec5d5-ec21-4958-b3e8-22a7a866a05a",
                                  "vulnId": "INT-001",
                                  "source": "INTERNAL",
                                  "aliases": [
                                    {
                                      "vulnId": "OSV-001",
                                      "source": "OSV"
                                    }
                                  ],
                                  "title": "vulnerabilityTitle",
                                  "subtitle": "vulnerabilitySubTitle",
                                  "description": "vulnerabilityDescription",
                                  "recommendation": "vulnerabilityRecommendation",
                                  "cvssv2": 5.5,
                                  "cvssv3": 6.6,
                                  "owaspRRLikelihood": 1.1,
                                  "owaspRRTechnicalImpact": 2.2,
                                  "owaspRRBusinessImpact": 3.3,
                                  "severity": "MEDIUM",
                                  "cwes": [
                                    {
                                      "cweId": 666,
                                      "name": "Operation on Resource in Wrong Phase of Lifetime"
                                    },
                                    {
                                      "cweId": 777,
                                      "name": "Regular Expression without Anchors"
                                    }
                                  ]
                                }
                              ]
                            }
                          }
                        }
                        """)));
    }

    @ParameterizedTest
    @ValueSource(ints = {429, 503})
    void shouldThrowRetryableExceptionWhenDestinationRespondsWithRetryableStatus(final int status) {
        WIREMOCK.stubFor(post(anyUrl())
                .willReturn(aResponse()
                        .withStatus(status)));

        assertThatExceptionOfType(RetryablePublishException.class)
                .isThrownBy(() -> publisher.publish(publishContext, createBomConsumedTestNotification()))
                .satisfies(exception -> Assertions.assertThat(exception.getRetryAfter()).isNull());
    }

    @ParameterizedTest
    @ValueSource(ints = {429, 503})
    void shouldThrowRetryableExceptionWhenDestinationRespondsWithRetryableStatusAndRetryAfterHeader(final int status) {
        WIREMOCK.stubFor(post(anyUrl())
                .willReturn(aResponse()
                        .withStatus(status)
                        .withHeader("Retry-After", "300")));

        assertThatExceptionOfType(RetryablePublishException.class)
                .isThrownBy(() -> publisher.publish(publishContext, createBomConsumedTestNotification()))
                .satisfies(exception -> Assertions.assertThat(exception.getRetryAfter()).hasMinutes(5));
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 401, 403, 405, 500, 504})
    void shouldThrowWhenDestinationRespondsWithNonRetryableStatus(final int status) {
        WIREMOCK.stubFor(post(anyUrl())
                .willReturn(aResponse()
                        .withStatus(status)));

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> publisher.publish(publishContext, createBomConsumedTestNotification()))
                .withMessage("Unexpected response code: " + status);
    }

}