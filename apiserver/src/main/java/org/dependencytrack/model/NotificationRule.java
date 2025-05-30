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
package org.dependencytrack.model;

import alpine.common.validation.RegexSequence;
import alpine.model.Team;
import alpine.notification.NotificationLevel;
import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.apache.commons.collections4.CollectionUtils;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.ForeignKey;
import javax.jdo.annotations.ForeignKeyAction;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Join;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * Defines a Model class for notification configurations.
 *
 * @author Steve Springett
 * @since 3.2.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class NotificationRule implements Serializable {

    private static final long serialVersionUID = 2534439091019367263L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    /**
     * The String representation of the name of the notification.
     */
    @Persistent
    @Column(name = "NAME", allowsNull = "false")
    @NotBlank
    @Size(min = 1, max = 255)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
    private String name;

    @Persistent
    @Column(name = "ENABLED")
    private boolean enabled;

    @Persistent
    @Column(name = "NOTIFY_CHILDREN", allowsNull = "true") // New column, must allow nulls on existing data bases)
    private boolean notifyChildren;

    /**
     * In addition to warnings and errors, also emit a log message upon successful publishing.
     * <p>
     * Intended to aid in debugging of missing notifications, or environments where notification
     * delivery is critical and subject to auditing.
     *
     * @since 4.10.0
     */
    @Persistent
    @Column(name = "LOG_SUCCESSFUL_PUBLISH", allowsNull = "true")
    private boolean logSuccessfulPublish;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "SCOPE", jdbcType = "VARCHAR", allowsNull = "false")
    @NotNull
    private NotificationScope scope;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "NOTIFICATION_LEVEL", jdbcType = "VARCHAR")
    private NotificationLevel notificationLevel;

    @Persistent(table = "NOTIFICATIONRULE_PROJECTS", defaultFetchGroup = "true")
    @Join(column = "NOTIFICATIONRULE_ID", foreignKey = "NOTIFICATIONRULE_PROJECTS_NOTIFICATIONRULE_FK", deleteAction = ForeignKeyAction.CASCADE)
    @Element(column = "PROJECT_ID", foreignKey = "NOTIFICATIONRULE_PROJECTS_PROJECT_FK", deleteAction = ForeignKeyAction.CASCADE)
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "name ASC, version ASC"))
    private List<Project> projects;

    @Persistent(table = "NOTIFICATIONRULE_TAGS", defaultFetchGroup = "true", mappedBy = "notificationRules")
    @Join(column = "NOTIFICATIONRULE_ID", primaryKey = "NOTIFICATIONRULE_TAGS_PK", foreignKey = "NOTIFICATIONRULE_TAGS_NOTIFICATIONRULE_FK", deleteAction = ForeignKeyAction.CASCADE)
    @Element(column = "TAG_ID", foreignKey = "NOTIFICATIONRULE_TAGS_TAG_FK", deleteAction = ForeignKeyAction.CASCADE)
    private Set<Tag> tags;

    @Persistent(table = "NOTIFICATIONRULE_TEAMS", defaultFetchGroup = "true")
    @Join(column = "NOTIFICATIONRULE_ID", primaryKey = "NOTIFICATIONRULE_TEAMS_PK", foreignKey = "NOTIFICATIONRULE_TEAMS_NOTIFICATIONRULE_FK", deleteAction = ForeignKeyAction.CASCADE)
    @Element(column = "TEAM_ID", foreignKey = "NOTIFICATIONRULE_TEAMS_TEAM_FK", deleteAction = ForeignKeyAction.CASCADE)
    private Set<Team> teams;

    @Persistent
    @Column(name = "NOTIFY_ON", length = 1024)
    private String notifyOn;

    @Persistent
    @Column(name = "MESSAGE", length = 1024)
    @Size(max = 1024)
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The message may only contain printable characters")
    private String message;

    @Persistent(defaultFetchGroup = "true")
    @ForeignKey(name = "NOTIFICATIONRULE_NOTIFICATIONPUBLISHER_FK", updateAction = ForeignKeyAction.NONE, deleteAction = ForeignKeyAction.CASCADE, deferred = "true")
    @Column(name = "PUBLISHER")
    private NotificationPublisher publisher;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "PUBLISHER_CONFIG", jdbcType = "CLOB")
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String publisherConfig;

    @Persistent(defaultFetchGroup = "true", customValueStrategy = "uuid")
    @Unique(name = "NOTIFICATIONRULE_UUID_IDX")
    @Column(name = "UUID", sqlType = "UUID", allowsNull = "false")
    @NotNull
    private UUID uuid;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    @NotNull
    public String getName() {
        return name;
    }

    public void setName(@NotNull String name) {
        this.name = name;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isNotifyChildren() {
        return notifyChildren;
    }

    public void setNotifyChildren(boolean notifyChildren) {
        this.notifyChildren = notifyChildren;
    }


    public boolean isLogSuccessfulPublish() {
        return logSuccessfulPublish;
    }

    public void setLogSuccessfulPublish(final boolean logSuccessfulPublish) {
        this.logSuccessfulPublish = logSuccessfulPublish;
    }

    @NotNull
    public NotificationScope getScope() {
        return scope;
    }

    public void setScope(@NotNull NotificationScope scope) {
        this.scope = scope;
    }

    public NotificationLevel getNotificationLevel() {
        return notificationLevel;
    }

    public void setNotificationLevel(NotificationLevel notificationLevel) {
        this.notificationLevel = notificationLevel;
    }

    public List<Project> getProjects() {
        return projects;
    }

    public void setProjects(List<Project> projects) {
        this.projects = projects;
    }

    public Set<Tag> getTags() {
        return tags;
    }

    public void setTags(final Set<Tag> tags) {
        this.tags = tags;
    }

    public Set<Team> getTeams() {
        return teams;
    }

    public void setTeams(Set<Team> teams) {
        this.teams = teams;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Set<NotificationGroup> getNotifyOn() {
        Set<NotificationGroup> result = new TreeSet<>();
        if (notifyOn != null) {
            String[] groups = notifyOn.split(",");
            for (String s: groups) {
                result.add(NotificationGroup.valueOf(s.trim()));
            }
        }
        return result;
    }

    public void setNotifyOn(Set<NotificationGroup> groups) {
        if (CollectionUtils.isEmpty(groups)) {
            this.notifyOn = null;
            return;
        }
        StringBuilder sb = new StringBuilder();
        List<NotificationGroup> list = new ArrayList<>(groups);
        Collections.sort(list);
        for (int i=0; i<list.size(); i++) {
            sb.append(list.get(i));
            if (i+1 < list.size()) {
                sb.append(",");
            }
        }
        this.notifyOn = sb.toString();
    }

    public NotificationPublisher getPublisher() {
        return publisher;
    }

    public void setPublisher(NotificationPublisher publisher) {
        this.publisher = publisher;
    }

    public String getPublisherConfig() {
        return publisherConfig;
    }

    public void setPublisherConfig(String publisherConfig) {
        this.publisherConfig = publisherConfig;
    }

    @NotNull
    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(@NotNull UUID uuid) {
        this.uuid = uuid;
    }
}
