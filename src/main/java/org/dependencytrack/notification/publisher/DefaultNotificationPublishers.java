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
package org.dependencytrack.notification.publisher;

import jakarta.ws.rs.core.MediaType;

import static org.dependencytrack.notification.publisher.PublisherClass.ConsolePublisher;
import static org.dependencytrack.notification.publisher.PublisherClass.CsWebexPublisher;
import static org.dependencytrack.notification.publisher.PublisherClass.JiraPublisher;
import static org.dependencytrack.notification.publisher.PublisherClass.MattermostPublisher;
import static org.dependencytrack.notification.publisher.PublisherClass.MsTeamsPublisher;
import static org.dependencytrack.notification.publisher.PublisherClass.SendMailPublisher;
import static org.dependencytrack.notification.publisher.PublisherClass.SlackPublisher;
import static org.dependencytrack.notification.publisher.PublisherClass.WebhookPublisher;

public enum DefaultNotificationPublishers {

    SLACK("Slack", "Publishes notifications to a Slack channel", SlackPublisher, "/templates/notification/publisher/slack.peb", MediaType.APPLICATION_JSON, true),
    MS_TEAMS("Microsoft Teams", "Publishes notifications to a Microsoft Teams channel", MsTeamsPublisher, "/templates/notification/publisher/msteams.peb", MediaType.APPLICATION_JSON, true),
    MATTERMOST("Mattermost", "Publishes notifications to a Mattermost channel", MattermostPublisher, "/templates/notification/publisher/mattermost.peb", MediaType.APPLICATION_JSON, true),
    EMAIL("Email", "Sends notifications to an email address", SendMailPublisher, "/templates/notification/publisher/email.peb", MediaType.TEXT_PLAIN, true),
    CONSOLE("Console", "Displays notifications on the system console", ConsolePublisher, "/templates/notification/publisher/console.peb", MediaType.TEXT_PLAIN, true),
    WEBHOOK("Outbound Webhook", "Publishes notifications to a configurable endpoint", WebhookPublisher, "/templates/notification/publisher/webhook.peb", MediaType.APPLICATION_JSON, true),
    CS_WEBEX("Cisco Webex", "Publishes notifications to a Cisco Webex Teams channel", CsWebexPublisher, "/templates/notification/publisher/cswebex.peb", MediaType.APPLICATION_JSON, true),
    JIRA("Jira", "Creates a Jira issue in a configurable Jira instance and queue", JiraPublisher, "/templates/notification/publisher/jira.peb", MediaType.APPLICATION_JSON, true);

    private String name;
    private String description;
    private PublisherClass publisherClass;
    private String templateFile;
    private String templateMimeType;
    private boolean defaultPublisher;

    DefaultNotificationPublishers(final String name, final String description, final PublisherClass publisherClass,
                                  final String templateFile, final String templateMimeType, final boolean defaultPublisher) {
        this.name = name;
        this.description = description;
        this.publisherClass = publisherClass;
        this.templateFile = templateFile;
        this.templateMimeType = templateMimeType;
        this.defaultPublisher = defaultPublisher;
    }

    public String getPublisherName() {
        return name;
    }

    public String getPublisherDescription() {
        return description;
    }

    public PublisherClass getPublisherClass() {
        return publisherClass;
    }

    public String getPublisherTemplateFile() {
        return templateFile;
    }

    public String getTemplateMimeType() {
        return templateMimeType;
    }

    public boolean isDefaultPublisher() {
        return defaultPublisher;
    }
}