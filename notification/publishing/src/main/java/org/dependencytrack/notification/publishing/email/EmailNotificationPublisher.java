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
import org.dependencytrack.notification.api.publishing.RetryablePublishException;
import org.dependencytrack.notification.api.templating.RenderedNotificationTemplate;
import org.dependencytrack.notification.proto.v1.Notification;
import org.eclipse.angus.mail.smtp.SMTPSendFailedException;
import org.eclipse.angus.mail.util.MailConnectException;

import javax.net.ssl.SSLSocketFactory;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.util.Collection;
import java.util.Map;
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

    private final Map<String, String> overrideMailProperties;
    private final Class<? extends SSLSocketFactory> sslSocketFactoryClass;
    private final EmailNotificationPublisherGlobalConfig globalConfig;

    EmailNotificationPublisher(
            Map<String, String> overrideMailProperties,
            Class<? extends SSLSocketFactory> sslSocketFactoryClass,
            EmailNotificationPublisherGlobalConfig globalConfig) {
        this.overrideMailProperties = overrideMailProperties;
        this.sslSocketFactoryClass = sslSocketFactoryClass;
        this.globalConfig = globalConfig;
    }

    @Override
    public void publish(NotificationPublishContext ctx, Notification notification) {
        final var ruleConfig = ctx.ruleConfig(EmailNotificationPublisherRuleConfig.class);

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

        final Session session = getSession(globalConfig);

        try {
            final var message = new MimeMessage(session);
            message.setSender(new InternetAddress(globalConfig.getSenderAddress()));
            message.setRecipients(Message.RecipientType.TO, recipients);
            message.setSubject(messageSubject);

            final var bodyPart = new MimeBodyPart();
            bodyPart.setText(renderedTemplate.content());

            final var multipart = new MimeMultipart();
            multipart.addBodyPart(bodyPart);
            message.setContent(multipart, renderedTemplate.mimeType());

            Transport.send(message);
        } catch (MessagingException e) {
            if (isRetryable(e)) {
                throw new RetryablePublishException("Failed to send email with retryable cause", e);
            }

            throw new IllegalStateException("Failed to send email", e);
        }
    }

    private Session getSession(EmailNotificationPublisherGlobalConfig globalConfig) {
        final Properties props = new Properties();
        props.put("mail.smtp.host", globalConfig.getHost());
        props.put("mail.smtp.port", globalConfig.getPort());
        props.put("mail.smtp.socketFactory.port", globalConfig.getPort());
        props.put("mail.smtp.connectiontimeout", TIMEOUT_MILLIS);
        props.put("mail.smtp.timeout", TIMEOUT_MILLIS);
        props.put("mail.smtp.writetimeout", TIMEOUT_MILLIS);

        final Boolean sslEnabled = globalConfig.getSslEnabled();
        if (sslEnabled != null && sslEnabled) {
            props.put("mail.smtp.ssl.enable", true);
            props.put("mail.smtp.socketFactory.class", sslSocketFactoryClass.getName());
            props.put("mail.smtp.socketFactory.fallback", "false");
        }

        final Boolean startTlsEnabled = globalConfig.getStartTlsEnabled();
        if (startTlsEnabled != null && startTlsEnabled) {
            props.put("mail.smtp.starttls.enable", true);
        }

        final boolean authenticated =
                globalConfig.getUsername() != null
                        && globalConfig.getPassword() != null;

        Authenticator authenticator = null;
        if (authenticated) {
            props.put("mail.smtp.auth", true);
            authenticator = new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(
                            globalConfig.getUsername(),
                            globalConfig.getPassword());
                }
            };
        }

        props.putAll(overrideMailProperties);

        return Session.getInstance(props, authenticator);
    }

    private boolean isRetryable(MessagingException e) {
        if (e instanceof MailConnectException
                || e.getCause() instanceof ConnectException
                || e.getCause() instanceof SocketTimeoutException) {
            return true;
        }

        if (e instanceof final SMTPSendFailedException ssfe) {
            return ssfe.getReturnCode() >= 400 && ssfe.getReturnCode() < 500;
        }

        return false;
    }

}
