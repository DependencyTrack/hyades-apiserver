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
package org.dependencytrack.notification.publishing.msteams;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.dependencytrack.notification.api.publishing.MutableNotificationRuleConfig;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.publishing.AbstractNotificationPublisherTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.RegisterExtension;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;

class MsTeamsNotificationPublisherTest extends AbstractNotificationPublisherTest {

    @RegisterExtension
    private static final WireMockExtension WIREMOCK = WireMockExtension.newInstance()
            .options(WireMockConfiguration.wireMockConfig().dynamicPort())
            .build();

    @Override
    protected NotificationPublisherFactory createPublisherFactory() {
        return new MsTeamsNotificationPublisherFactory();
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
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "@type": "MessageCard",
                          "@context": "http://schema.org/extensions",
                          "summary": "Bill of Materials Consumed",
                          "title": "Bill of Materials Consumed",
                          "sections": [
                            {
                              "activityTitle": "Dependency-Track",
                              "activitySubtitle": "2006-06-06T06:06:06.666Z",
                              "activityImage": "https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-logo-symbol-blue-background.png",
                              "facts": [
                                {
                                  "name": "Level",
                                  "value": "LEVEL_INFORMATIONAL"
                                },
                                {
                                  "name": "Scope",
                                  "value": "SCOPE_PORTFOLIO"
                                },
                                {
                                  "name": "Group",
                                  "value": "GROUP_BOM_CONSUMED"
                                }
                              ],
                              "text": "A CycloneDX BOM was consumed and will be processed"
                            }
                          ]
                        }
                        """)));
    }

    @Override
    protected void validateBomProcessingFailedNotificationPublish(final Notification ignored) {
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "@type": "MessageCard",
                          "@context": "http://schema.org/extensions",
                          "summary": "Bill of Materials Processing Failed",
                          "title": "Bill of Materials Processing Failed",
                          "sections": [
                            {
                              "activityTitle": "Dependency-Track",
                              "activitySubtitle": "2006-06-06T06:06:06.666Z",
                              "activityImage": "https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-logo-symbol-blue-background.png",
                              "facts": [
                                {
                                  "name": "Level",
                                  "value": "LEVEL_ERROR"
                                },
                                {
                                  "name": "Scope",
                                  "value": "SCOPE_PORTFOLIO"
                                },
                                {
                                  "name": "Group",
                                  "value": "GROUP_BOM_PROCESSING_FAILED"
                                },
                                {
                                  "name": "Project",
                                  "value": "pkg:maven/org.acme/projectName@projectVersion"
                                },
                                {
                                  "name": "Project URL",
                                  "value": "https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95"
                                }
                              ],
                              "text": "An error occurred while processing a BOM"
                            }
                          ]
                        }
                        """)));
    }

    @Override
    protected void validateBomValidationFailedNotificationPublish(final Notification ignored) {
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "@type": "MessageCard",
                          "@context": "http://schema.org/extensions",
                          "summary": "Bill of Materials Validation Failed",
                          "title": "Bill of Materials Validation Failed",
                          "sections": [
                            {
                              "activityTitle": "Dependency-Track",
                              "activitySubtitle": "2006-06-06T06:06:06.666Z",
                              "activityImage": "https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-logo-symbol-blue-background.png",
                              "facts": [
                                {
                                  "name": "Level",
                                  "value": "LEVEL_ERROR"
                                },
                                {
                                  "name": "Scope",
                                  "value": "SCOPE_PORTFOLIO"
                                },
                                {
                                  "name": "Group",
                                  "value": "GROUP_BOM_VALIDATION_FAILED"
                                }
                              ],
                              "text": "An error occurred while validating a BOM"
                            }
                          ]
                        }
                        """)));
    }

    @Override
    protected void validateNewVulnerabilityNotificationPublish(final Notification ignored) {
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "@type": "MessageCard",
                          "@context": "http://schema.org/extensions",
                          "summary": "New Vulnerability Identified on Project: [projectName : projectVersion]",
                          "title": "New Vulnerability Identified on Project: [projectName : projectVersion]",
                          "sections": [
                            {
                              "activityTitle": "Dependency-Track",
                              "activitySubtitle": "2006-06-06T06:06:06.666Z",
                              "activityImage": "https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-logo-symbol-blue-background.png",
                              "facts": [
                                {
                                  "name": "VulnID",
                                  "value": "INT-001"
                                },
                                {
                                  "name": "Severity",
                                  "value": "MEDIUM"
                                },
                                {
                                  "name": "Source",
                                  "value": "INTERNAL"
                                },
                                {
                                  "name": "Component",
                                  "value": "componentName : componentVersion"
                                }
                              ],
                              "text": "vulnerabilityDescription"
                            }
                          ]
                        }
                        """)));
    }

    @Override
    protected void validateNewVulnerableDependencyNotificationPublish(final Notification ignored) {
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "@type": "MessageCard",
                          "@context": "http://schema.org/extensions",
                          "summary": "Vulnerable Dependency Introduced on Project: [projectName : projectVersion]",
                          "title": "Vulnerable Dependency Introduced on Project: [projectName : projectVersion]",
                          "sections": [
                            {
                              "activityTitle": "Dependency-Track",
                              "activitySubtitle": "2006-06-06T06:06:06.666Z",
                              "activityImage": "https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-logo-symbol-blue-background.png",
                              "facts": [
                                {
                                  "name": "Project",
                                  "value": "pkg:maven/org.acme/projectName@projectVersion"
                                },
                                {
                                  "name": "Component",
                                  "value": "componentName : componentVersion"
                                }
                              ],
                              "text": "A dependency was introduced that contains 1 known vulnerability"
                            }
                          ]
                        }
                        """)));
    }

}