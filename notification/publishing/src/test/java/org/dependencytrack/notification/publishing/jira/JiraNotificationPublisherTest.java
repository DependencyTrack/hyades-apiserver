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
package org.dependencytrack.notification.publishing.jira;

import com.github.tomakehurst.wiremock.client.BasicCredentials;
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
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherRuleConfigs.PASSWORD_OR_TOKEN_CONFIG;
import static org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherRuleConfigs.PROJECT_KEY_CONFIG;
import static org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherRuleConfigs.TICKET_TYPE_CONFIG;
import static org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherRuleConfigs.USERNAME_CONFIG;

class JiraNotificationPublisherTest extends AbstractNotificationPublisherTest {

    @RegisterExtension
    private static final WireMockExtension WIREMOCK = WireMockExtension.newInstance()
            .options(wireMockConfig().dynamicPort())
            .build();

    @Override
    protected NotificationPublisherFactory createPublisherFactory() {
        return new JiraNotificationPublisherFactory();
    }

    @Override
    protected void customizeRuleConfig(final MutableNotificationRuleConfig ruleConfig) {
        ruleConfig.setValue(USERNAME_CONFIG, "username");
        ruleConfig.setValue(PASSWORD_OR_TOKEN_CONFIG, "password");
        ruleConfig.setValue(PROJECT_KEY_CONFIG, "FOO");
        ruleConfig.setValue(TICKET_TYPE_CONFIG, "TASK");
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
                        .withStatus(201)));
    }

    @Override
    protected void validateBomConsumedNotificationPublish(final Notification ignored) {
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                .withBasicAuth(new BasicCredentials("username", "password"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "fields": {
                            "project": {
                              "key": "FOO"
                            },
                            "issuetype": {
                              "name": "TASK"
                            },
                            "summary": "[Dependency-Track] [GROUP_BOM_CONSUMED] Bill of Materials Consumed",
                            "description": "A CycloneDX BOM was consumed and will be processed\\n\\\\\\\\\\n\\\\\\\\\\n*Level*\\nLEVEL_INFORMATIONAL\\n\\n"
                          }
                        }
                        """)));
    }

    @Override
    protected void validateBomProcessingFailedNotificationPublish(final Notification ignored) {
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                .withBasicAuth(new BasicCredentials("username", "password"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "fields": {
                            "project": {
                              "key": "FOO"
                            },
                            "issuetype": {
                              "name": "TASK"
                            },
                            "summary": "[Dependency-Track] [GROUP_BOM_PROCESSING_FAILED] Bill of Materials Processing Failed",
                            "description": "An error occurred while processing a BOM\\n\\\\\\\\\\n\\\\\\\\\\n*Level*\\nLEVEL_ERROR\\n\\n"
                          }
                        }
                        """)));
    }

    @Override
    protected void validateBomValidationFailedNotificationPublish(final Notification ignored) {
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                .withBasicAuth(new BasicCredentials("username", "password"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "fields": {
                            "project": {
                              "key": "FOO"
                            },
                            "issuetype": {
                              "name": "TASK"
                            },
                            "summary": "[Dependency-Track] [GROUP_BOM_VALIDATION_FAILED] Bill of Materials Validation Failed",
                            "description": "An error occurred while validating a BOM\\n\\\\\\\\\\n\\\\\\\\\\n*Level*\\nLEVEL_ERROR\\n\\n"
                          }
                        }
                        """)));
    }

    @Override
    protected void validateNewVulnerabilityNotificationPublish(final Notification ignored) {
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                .withBasicAuth(new BasicCredentials("username", "password"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "fields": {
                            "project": {
                              "key": "FOO"
                            },
                            "issuetype": {
                              "name": "TASK"
                            },
                            "summary": "[Dependency-Track] [GROUP_NEW_VULNERABILITY] [MEDIUM] New medium vulnerability identified: INT-001",
                            "description": "A new vulnerability has been identified on your project(s).\\n\\\\\\\\\\n\\\\\\\\\\n*Vulnerability description*\\n{code:none|bgColor=white|borderStyle=none}vulnerabilityDescription{code}\\n\\n*VulnID*\\nINT-001\\n\\n*Severity*\\nMedium\\n\\n*Component*\\n[componentName : componentVersion|https://example.com/components/94f87321-a5d1-4c2f-b2fe-95165debebc6]\\n\\n*Affected project(s)*\\n- [projectName (projectVersion)|https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95]\\n"
                          }
                        }
                        """)));
    }

    @Override
    protected void validateNewVulnerableDependencyNotificationPublish(final Notification ignored) {
        WIREMOCK.verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                .withBasicAuth(new BasicCredentials("username", "password"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
                        {
                          "fields": {
                            "project": {
                              "key": "FOO"
                            },
                            "issuetype": {
                              "name": "TASK"
                            },
                            "summary": "[Dependency-Track] [GROUP_NEW_VULNERABLE_DEPENDENCY] Vulnerable dependency introduced on project projectName",
                            "description": "A component which contains one or more vulnerabilities has been added to your project.\\n\\\\\\\\\\n\\\\\\\\\\n*Project*\\n[pkg:maven/org.acme/projectName@projectVersion|https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95]\\n\\n*Component*\\n[componentName : componentVersion|https://example.com/components/94f87321-a5d1-4c2f-b2fe-95165debebc6]\\n\\n*Vulnerabilities*\\n- INT-001 (Medium)\\n"
                          }
                        }
                        """)));
    }

}