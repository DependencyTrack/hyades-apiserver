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

import com.github.benmanes.caffeine.cache.Cache;
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
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationRuleConfig;
import org.dependencytrack.notification.api.publishing.PublishContext;
import org.dependencytrack.notification.api.templating.RenderedTemplate;
import org.dependencytrack.notification.proto.v1.Notification;

import java.util.Objects;
import java.util.Properties;

import static org.dependencytrack.notification.publishing.email.EmailNotificationPublisherRuleConfigs.PASSWORD_CONFIG;
import static org.dependencytrack.notification.publishing.email.EmailNotificationPublisherRuleConfigs.SMTP_FROM_ADDRESS_CONFIG;
import static org.dependencytrack.notification.publishing.email.EmailNotificationPublisherRuleConfigs.SMTP_HOST_CONFIG;
import static org.dependencytrack.notification.publishing.email.EmailNotificationPublisherRuleConfigs.SMTP_PORT_CONFIG;
import static org.dependencytrack.notification.publishing.email.EmailNotificationPublisherRuleConfigs.SUBJECT_PREFIX_CONFIG;
import static org.dependencytrack.notification.publishing.email.EmailNotificationPublisherRuleConfigs.USERNAME_CONFIG;

/**
 * @since 5.7.0
 */
final class EmailNotificationPublisher implements NotificationPublisher {

    private final Cache<SessionCacheKey, Session> sessionCache;

    EmailNotificationPublisher(final Cache<SessionCacheKey, Session> sessionCache) {
        this.sessionCache = sessionCache;
    }

    @Override
    public void publish(final PublishContext ctx, final Notification notification) {
        if (ctx.destination() == null) {
            throw new IllegalStateException("No destination configured");
        }

        final RenderedTemplate renderedTemplate = ctx.templateRenderer().render(notification);
        if (renderedTemplate == null) {
            throw new IllegalStateException("No template configured");
        }

        // TODO: When rule is associated with teams, use email addresses of team members.

        final String messageSubject = "%s %s".formatted(
                ctx.ruleConfig().getOptionalValue(SUBJECT_PREFIX_CONFIG).orElse(""),
                notification.getTitle()).trim();

        final Session session = getSession(ctx.ruleConfig());

        try {
            final var message = new MimeMessage(session);
            message.setSender(new InternetAddress(
                    ctx.ruleConfig().getValue(SMTP_FROM_ADDRESS_CONFIG)));
            message.setRecipient(
                    Message.RecipientType.TO,
                    new InternetAddress(ctx.destination()));
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

    private Session getSession(final NotificationRuleConfig ruleConfig) {
        final String smtpHost = ruleConfig.getValue(SMTP_HOST_CONFIG);
        final int smtpPort = ruleConfig.getValue(SMTP_PORT_CONFIG);
        final String username = ruleConfig.getOptionalValue(USERNAME_CONFIG).orElse(null);
        final String password = ruleConfig.getOptionalValue(PASSWORD_CONFIG).orElse(null);

        final Properties props = new Properties();
        props.put("mail.smtp.host", smtpHost);
        props.put("mail.smtp.port", smtpPort);
        props.put("mail.smtp.socketFactory.port", smtpPort);
        // props.put("mail.smtp.auth", smtpauth);
        // props.put("mail.smtp.starttls.enable", useStartTLS);

        return sessionCache.get(
                new SessionCacheKey(props, Objects.hash(username, password)),
                ignored -> {
                    Authenticator authenticator = null;
                    if (username != null && password != null) {
                        authenticator = new Authenticator() {
                            protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication(username, password);
                            }
                        };
                    }

                    return Session.getInstance(props, authenticator);
                });
    }

}
