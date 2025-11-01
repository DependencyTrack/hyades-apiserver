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
package org.dependencytrack.notification.publishing.slack;

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

class SlackNotificationPublisherTest extends AbstractNotificationPublisherTest {

    @RegisterExtension
    private static final WireMockExtension WIREMOCK = WireMockExtension.newInstance()
            .options(WireMockConfiguration.wireMockConfig().dynamicPort())
            .build();

    @Override
    protected NotificationPublisherFactory createPublisherFactory() {
        return new SlackNotificationPublisherFactory();
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
                          "blocks": [
                            {
                              "type": "header",
                              "text": {
                                "type": "plain_text",
                                "text": "GROUP_BOM_CONSUMED"
                              }
                            },
                            {
                              "type": "context",
                              "elements": [
                                {
                                  "text": "*LEVEL_INFORMATIONAL*  |  *SCOPE_PORTFOLIO*",
                                  "type": "mrkdwn"
                                }
                              ]
                            },
                            {
                              "type": "divider"
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "Bill of Materials Consumed",
                                "type": "plain_text"
                              }
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "A CycloneDX BOM was consumed and will be processed",
                                "type": "plain_text"
                              }
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
                          "blocks": [
                            {
                              "type": "header",
                              "text": {
                                "type": "plain_text",
                                "text": "GROUP_BOM_PROCESSING_FAILED"
                              }
                            },
                            {
                              "type": "context",
                              "elements": [
                                {
                                  "text": "*LEVEL_ERROR*  |  *SCOPE_PORTFOLIO*",
                                  "type": "mrkdwn"
                                }
                              ]
                            },
                            {
                              "type": "divider"
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "Bill of Materials Processing Failed",
                                "type": "plain_text"
                              }
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "An error occurred while processing a BOM",
                                "type": "plain_text"
                              }
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
                          "blocks": [
                            {
                              "type": "header",
                              "text": {
                                "type": "plain_text",
                                "text": "GROUP_BOM_VALIDATION_FAILED"
                              }
                            },
                            {
                              "type": "context",
                              "elements": [
                                {
                                  "text": "*LEVEL_ERROR*  |  *SCOPE_PORTFOLIO*",
                                  "type": "mrkdwn"
                                }
                              ]
                            },
                            {
                              "type": "divider"
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "Bill of Materials Validation Failed",
                                "type": "plain_text"
                              }
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "An error occurred while validating a BOM",
                                "type": "plain_text"
                              }
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
                          "blocks": [
                            {
                              "type": "header",
                              "text": {
                                "type": "plain_text",
                                "text": "New Vulnerability"
                              }
                            },
                            {
                              "type": "context",
                              "elements": [
                                {
                                  "text": "*LEVEL_INFORMATIONAL*  |  *SCOPE_PORTFOLIO*",
                                  "type": "mrkdwn"
                                }
                              ]
                            },
                            {
                              "type": "divider"
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "New Vulnerability Identified on Project: [projectName : projectVersion]",
                                "type": "mrkdwn"
                              },
                              "fields": [
                                {
                                  "type": "mrkdwn",
                                  "text": "*VulnID*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "INT-001"
                                },
                                {
                                  "type": "mrkdwn",
                                  "text": "*Severity*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "MEDIUM"
                                },
                                {
                                  "type": "mrkdwn",
                                  "text": "*Source*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "INTERNAL"
                                },
                                {
                                  "type": "mrkdwn",
                                  "text": "*Component*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "componentName : componentVersion"
                                }
                              ]
                            },
                            {
                              "type": "actions",
                              "elements": [
                                {
                                  "type": "button",
                                  "text": {
                                    "type": "plain_text",
                                    "text": "View Vulnerability"
                                  },
                                  "action_id": "actionId-1",
                                  "url": "https://example.com/vulnerabilities/INTERNAL/INT-001"
                                },
                                {
                                  "type": "button",
                                  "text": {
                                    "type": "plain_text",
                                    "text": "View Component"
                                  },
                                  "action_id": "actionId-2",
                                  "url": "https://example.com/components/94f87321-a5d1-4c2f-b2fe-95165debebc6"
                                }
                              ]
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
                          "blocks": [
                            {
                              "type": "header",
                              "text": {
                                "type": "plain_text",
                                "text": "New Vulnerable Dependency"
                              }
                            },
                            {
                              "type": "context",
                              "elements": [
                                {
                                  "text": "*LEVEL_INFORMATIONAL*  |  *SCOPE_PORTFOLIO*",
                                  "type": "mrkdwn"
                                }
                              ]
                            },
                            {
                              "type": "divider"
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "Vulnerable Dependency Introduced on Project: [projectName : projectVersion]",
                                "type": "mrkdwn"
                              },
                              "fields": [
                                {
                                  "type": "mrkdwn",
                                  "text": "*Component*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "componentName : componentVersion"
                                },
                                {
                                  "type": "mrkdwn",
                                  "text": "*Project*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "pkg:maven/org.acme/projectName@projectVersion"
                                }
                              ]
                            },
                            {
                              "type": "actions",
                              "elements": [
                                {
                                  "type": "button",
                                  "text": {
                                    "type": "plain_text",
                                    "text": "View Project"
                                  },
                                  "action_id": "actionId-1",
                                  "url": "https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95"
                                },
                                {
                                  "type": "button",
                                  "text": {
                                    "type": "plain_text",
                                    "text": "View Component"
                                  },
                                  "action_id": "actionId-2",
                                  "url": "https://example.com/components/94f87321-a5d1-4c2f-b2fe-95165debebc6"
                                }
                              ]
                            }
                          ]
                        }
                        """)));
    }

}