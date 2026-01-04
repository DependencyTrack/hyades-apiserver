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

import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.dependencytrack.notification.api.publishing.NotificationPublishContext;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationRuleContact;
import org.dependencytrack.notification.api.templating.RenderedNotificationTemplate;
import org.dependencytrack.notification.proto.v1.Notification;

import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @since 5.7.0
 */
final class EmailNotificationPublisher implements NotificationPublisher {

    private static final long TIMEOUT_MILLIS = TimeUnit.SECONDS.toMillis(10);

    @Override
    public void publish(NotificationPublishContext ctx, Notification notification) {
        final var ruleConfig = ctx.ruleConfig(EmailNotificationRuleConfig.class);

        final RenderedNotificationTemplate renderedTemplate = ctx.templateRenderer().render(notification);
        if (renderedTemplate == null) {
            throw new IllegalStateException("No template configured");
        }

        final String recipients = Stream.concat(
                        Optional.ofNullable(ruleConfig.getRecipientAddresses()).stream()
                                .flatMap(Collection::stream)
                                .filter(Objects::nonNull),
                        ctx.ruleContacts().stream()
                                .map(NotificationRuleContact::email)
                                .filter(Objects::nonNull))
                .collect(Collectors.joining(","));
        if (recipients.isEmpty()) {
            throw new IllegalStateException("No recipients configured");
        }

        final String messageSubject = "%s %s".formatted(
                ruleConfig.getSubjectPrefix() != null
                        ? ruleConfig.getSubjectPrefix()
                        : "",
                notification.getTitle()).trim();

        final Session session = getSession(ruleConfig);

        try {
            final var message = new MimeMessage(session);
            message.setSender(new InternetAddress(ruleConfig.getSenderAddress()));
            message.setRecipients(Message.RecipientType.TO, recipients);
            message.setSubject(messageSubject);

            final var bodyPart = new MimeBodyPart();
            bodyPart.setText(renderedTemplate.content());

            final var multipart = new MimeMultipart();
            multipart.addBodyPart(bodyPart);
            message.setContent(multipart);

            Transport.send(message);
        } catch (MessagingException e) {
            throw new IllegalStateException(e);
        }
    }

    private Session getSession(EmailNotificationRuleConfig ruleConfig) {
        final boolean authenticated =
                ruleConfig.getSmtp().getUsername() != null
                        && ruleConfig.getSmtp().getPassword() != null;

        final Properties props = new Properties();
        props.put("mail.smtp.host", ruleConfig.getSmtp().getHost());
        props.put("mail.smtp.port", ruleConfig.getSmtp().getPort());
        props.put("mail.smtp.socketFactory.port", ruleConfig.getSmtp().getPort());
        if (authenticated) {
            props.put("mail.smtp.auth", true);
        }
        // props.put("mail.smtp.starttls.enable", useStartTLS);
        props.put("mail.smtp.connectiontimeout", TIMEOUT_MILLIS);
        props.put("mail.smtp.timeout", TIMEOUT_MILLIS);
        props.put("mail.smtp.writetimeout", TIMEOUT_MILLIS);

        Authenticator authenticator = null;
        if (authenticated) {
            authenticator = new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(
                            ruleConfig.getSmtp().getUsername(),
                            ruleConfig.getSmtp().getPassword());
                }
            };
        }

        return Session.getInstance(props, authenticator);
    }

}
