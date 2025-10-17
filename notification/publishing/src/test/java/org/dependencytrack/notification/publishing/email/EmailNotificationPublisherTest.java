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
package org.dependencytrack.notification.publishing.email;

import com.icegreen.greenmail.junit5.GreenMailExtension;
import com.icegreen.greenmail.util.ServerSetup;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.publishing.AbstractNotificationPublisherTest;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Set;

import static com.icegreen.greenmail.configuration.GreenMailConfiguration.aConfig;
import static org.assertj.core.api.Assertions.assertThat;

class EmailNotificationPublisherTest extends AbstractNotificationPublisherTest {

    @RegisterExtension
    private static final GreenMailExtension GREEN_MAIL =
            new GreenMailExtension(ServerSetup.SMTP.dynamicPort())
                    .withConfiguration(aConfig().withUser("username", "password"));

    @Override
    protected NotificationPublisherFactory createPublisherFactory() {
        return new EmailNotificationPublisherFactory();
    }

    @Override
    protected void customizeRuleConfig(RuntimeConfig ruleConfig) {
        final var emailRuleConfig = (EmailNotificationRuleConfig) ruleConfig;

        emailRuleConfig
                .withSmtp(new Smtp()
                        .withHost(GREEN_MAIL.getSmtp().getBindTo())
                        .withPort(GREEN_MAIL.getSmtp().getPort())
                        .withUsername("username")
                        .withPassword("password"))
                .withRecipientAddresses(Set.of("username@example.com"));
    }

    @Override
    protected void validateBomConsumedNotificationPublish(Notification ignored) {
        final ReceivedMessage message = getReceivedMessage();
        assertThat(message.subject()).isEqualTo("[Dependency-Track] Bill of Materials Consumed");
        assertThat(message.content()).isEqualToNormalizingNewlines("""
                Bill of Materials Consumed
                
                --------------------------------------------------------------------------------
                
                Project:           projectName
                Version:           projectVersion
                Description:       projectDescription
                Project URL:       https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                
                --------------------------------------------------------------------------------
                
                A CycloneDX BOM was consumed and will be processed
                
                --------------------------------------------------------------------------------
                
                2006-06-06T06:06:06.666Z
                """);
    }

    @Override
    protected void validateBomProcessingFailedNotificationPublish(Notification ignored) {
        final ReceivedMessage message = getReceivedMessage();
        assertThat(message.subject()).isEqualTo("[Dependency-Track] Bill of Materials Processing Failed");
        assertThat(message.content()).isEqualToNormalizingNewlines("""
                Bill of Materials Processing Failed
                
                --------------------------------------------------------------------------------
                
                Project:           projectName
                Version:           projectVersion
                Description:       projectDescription
                Project URL:       https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                
                --------------------------------------------------------------------------------
                
                Cause:
                cause
                
                --------------------------------------------------------------------------------
                
                An error occurred while processing a BOM
                
                --------------------------------------------------------------------------------
                
                2006-06-06T06:06:06.666Z
                """);
    }

    @Override
    protected void validateBomValidationFailedNotificationPublish(Notification ignored) {
        final ReceivedMessage message = getReceivedMessage();
        assertThat(message.subject()).isEqualTo("[Dependency-Track] Bill of Materials Validation Failed");
        assertThat(message.content()).isEqualToNormalizingNewlines("""
                Bill of Materials Validation Failed
                
                --------------------------------------------------------------------------------
                
                Project:           projectName
                Version:           projectVersion
                Description:       projectDescription
                Project URL:       https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                
                --------------------------------------------------------------------------------
                
                Errors:
                
                cause 1
                
                cause 2
                
                
                --------------------------------------------------------------------------------
                
                An error occurred while validating a BOM
                
                --------------------------------------------------------------------------------
                
                2006-06-06T06:06:06.666Z
                """);
    }

    @Override
    protected void validateNewVulnerabilityNotificationPublish(Notification ignored) {
        final ReceivedMessage message = getReceivedMessage();
        assertThat(message.subject()).isEqualTo("[Dependency-Track] New Vulnerability Identified on Project: [projectName : projectVersion]");
        assertThat(message.content()).isEqualToNormalizingNewlines("""
                New Vulnerability Identified on Project: [projectName : projectVersion]
                
                --------------------------------------------------------------------------------
                
                Vulnerability ID:  INT-001
                Vulnerability URL: https://example.com/vulnerability/?source=INTERNAL&vulnId=INT-001
                Severity:          MEDIUM
                Source:            INTERNAL
                Component:         componentName : componentVersion
                Component URL:     https://example.com/component/?uuid=94f87321-a5d1-4c2f-b2fe-95165debebc6
                Project:           projectName
                Version:           projectVersion
                Description:       projectDescription
                Project URL:       https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                --------------------------------------------------------------------------------
                
                Other affected projects: https://example.com/vulnerabilities/INTERNAL/INT-001/affectedProjects
                
                --------------------------------------------------------------------------------
                
                vulnerabilityDescription
                
                --------------------------------------------------------------------------------
                
                2006-06-06T06:06:06.666Z
                """);
    }

    @Override
    protected void validateNewVulnerableDependencyNotificationPublish(Notification ignored) {
        final ReceivedMessage message = getReceivedMessage();
        assertThat(message.subject()).isEqualTo("[Dependency-Track] Vulnerable Dependency Introduced on Project: [projectName : projectVersion]");
        assertThat(message.content()).isEqualToNormalizingNewlines("""
                Vulnerable Dependency Introduced on Project: [projectName : projectVersion]
                
                --------------------------------------------------------------------------------
                
                Project:           pkg:maven/org.acme/projectName@projectVersion
                Project URL:       https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95
                Component:         componentName : componentVersion
                Component URL:     https://example.com/component/?uuid=94f87321-a5d1-4c2f-b2fe-95165debebc6
                
                Vulnerabilities
                
                Vulnerability ID:  INT-001
                Vulnerability URL: https://example.com/vulnerability/?source=INTERNAL&vulnId=INT-001
                Severity:          MEDIUM
                Source:            INTERNAL
                Description:
                vulnerabilityDescription
                
                
                
                --------------------------------------------------------------------------------
                
                A dependency was introduced that contains 1 known vulnerability
                
                --------------------------------------------------------------------------------
                
                2006-06-06T06:06:06.666Z
                """);
    }

    private record ReceivedMessage(String subject, String content) {
    }

    private ReceivedMessage getReceivedMessage() {
        final MimeMessage[] messages = GREEN_MAIL.getReceivedMessages();
        assertThat(messages).hasSize(1);

        try {
            final MimeMessage message = messages[0];
            assertThat(message.getContent()).isInstanceOf(MimeMultipart.class);

            final MimeMultipart content = (MimeMultipart) message.getContent();
            assertThat(content.getCount()).isEqualTo(1);
            assertThat(content.getBodyPart(0)).isInstanceOf(MimeBodyPart.class);

            return new ReceivedMessage(
                    message.getSubject(),
                    (String) content.getBodyPart(0).getContent());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (MessagingException e) {
            throw new IllegalStateException(e);
        }
    }

}