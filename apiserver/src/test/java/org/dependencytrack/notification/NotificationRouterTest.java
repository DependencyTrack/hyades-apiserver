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
package org.dependencytrack.notification;

import com.google.protobuf.Any;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.Notification;
import org.jdbi.v3.core.Handle;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.notification.ModelConverter.convert;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

@RunWith(JUnitParamsRunner.class)
public class NotificationRouterTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private NotificationRouter router;

    @Override
    public void before() throws Exception {
        super.before();

        jdbiHandle = openJdbiHandle();
        router = new NotificationRouter(jdbiHandle, new SimpleMeterRegistry());
    }

    @Override
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }

        super.after();
    }

    @Test
    public void constructorShouldThrowWhenJdbiHandleIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new NotificationRouter(null, new SimpleMeterRegistry()))
                .withMessage("jdbiHandle must not be null");
    }

    @Test
    public void constructorShouldThrowWhenMeterRegistryIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new NotificationRouter(jdbiHandle, null))
                .withMessage("meterRegistry must not be null");
    }

    @Test
    public void routeShouldThrowWhenNotificationsIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> router.route(null))
                .withMessage("notifications must not be null");
    }

    @Test
    public void routeShouldReturnEmptyListWhenNotificationsIsEmpty() {
        assertThat(router.route(Collections.emptyList())).isEmpty();
    }

    @Test
    public void routeShouldMatchEnabledRules() {
        // Create a rule that is enabled.
        final var enabledRule = new NotificationRule();
        enabledRule.setName("A");
        enabledRule.setScope(NotificationScope.PORTFOLIO);
        enabledRule.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
        enabledRule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        enabledRule.setEnabled(true);
        qm.persist(enabledRule);

        // Create a rule that disabled.
        final var disabledRule = new NotificationRule();
        disabledRule.setName("B");
        disabledRule.setScope(NotificationScope.PORTFOLIO);
        disabledRule.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
        disabledRule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        disabledRule.setEnabled(false);
        qm.persist(disabledRule);

        final Notification notification = TestNotificationFactory.createBomConsumedTestNotification();

        // Only the enabled rule should have matched.
        assertThat(router.route(List.of(notification))).satisfiesExactly(task -> {
            assertThat(task.ruleId()).isEqualTo(enabledRule.getId());
            assertThat(task.ruleName()).isEqualTo(enabledRule.getName());
            assertThat(task.notification()).isEqualTo(notification);
        });
    }

    @Test
    public void routeShouldMatchRulesWithMatchingProject() throws Exception {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        // Create a rule that is limited to project A.
        final var ruleProjectA = new NotificationRule();
        ruleProjectA.setName("A");
        ruleProjectA.setScope(NotificationScope.PORTFOLIO);
        ruleProjectA.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
        ruleProjectA.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        ruleProjectA.setEnabled(true);
        ruleProjectA.setProjects(List.of(projectA));
        qm.persist(ruleProjectA);

        // Create a rule that is limited to project B.
        final var ruleProjectB = new NotificationRule();
        ruleProjectB.setName("B");
        ruleProjectB.setScope(NotificationScope.PORTFOLIO);
        ruleProjectB.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
        ruleProjectB.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        ruleProjectB.setEnabled(true);
        ruleProjectB.setProjects(List.of(projectB));
        qm.persist(ruleProjectB);

        // Create a notification for project A.
        final Notification.Builder notificationBuilder =
                TestNotificationFactory.createBomConsumedTestNotification().toBuilder();
        final BomConsumedOrProcessedSubject.Builder subjectBuilder =
                notificationBuilder.getSubject().unpack(BomConsumedOrProcessedSubject.class).toBuilder();
        subjectBuilder.setProject(
                org.dependencytrack.proto.notification.v1.Project.newBuilder()
                        .setUuid(projectA.getUuid().toString())
                        .setName(projectA.getName())
                        .build());
        final Notification notification = notificationBuilder
                .setSubject(Any.pack(subjectBuilder.build()))
                .build();

        // Only the rule limited to project A must have matched.
        assertThat(router.route(List.of(notification))).satisfiesExactly(task -> {
            assertThat(task.ruleId()).isEqualTo(ruleProjectA.getId());
            assertThat(task.ruleName()).isEqualTo(ruleProjectA.getName());
            assertThat(task.notification()).isEqualTo(notification);
        });
    }

    @Test
    public void routeShouldMatchRulesWithMatchingParentProject() throws Exception {
        final var parentProject = new Project();
        parentProject.setName("acme-app-parent");
        qm.persist(parentProject);

        final var childProject = new Project();
        childProject.setParent(parentProject);
        childProject.setName("acme-app-child");
        qm.persist(childProject);

        // Create a rule that is limited to the parent project,
        // but has the "notify children" feature ENABLED.
        final var ruleNotifyChildren = new NotificationRule();
        ruleNotifyChildren.setName("A");
        ruleNotifyChildren.setScope(NotificationScope.PORTFOLIO);
        ruleNotifyChildren.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
        ruleNotifyChildren.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        ruleNotifyChildren.setEnabled(true);
        ruleNotifyChildren.setProjects(List.of(parentProject));
        ruleNotifyChildren.setNotifyChildren(true);
        qm.persist(ruleNotifyChildren);

        // Create a rule that is limited to the parent project,
        // but has the "notify children" feature DISABLED.
        final var ruleDoNotNotifyChildren = new NotificationRule();
        ruleDoNotNotifyChildren.setName("B");
        ruleDoNotNotifyChildren.setScope(NotificationScope.PORTFOLIO);
        ruleDoNotNotifyChildren.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
        ruleDoNotNotifyChildren.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        ruleDoNotNotifyChildren.setEnabled(true);
        ruleDoNotNotifyChildren.setProjects(List.of(parentProject));
        ruleDoNotNotifyChildren.setNotifyChildren(false);
        qm.persist(ruleDoNotNotifyChildren);

        // Create a notification for the child project.
        final Notification.Builder notificationBuilder =
                TestNotificationFactory.createBomConsumedTestNotification().toBuilder();
        final BomConsumedOrProcessedSubject.Builder subjectBuilder =
                notificationBuilder.getSubject().unpack(BomConsumedOrProcessedSubject.class).toBuilder();
        subjectBuilder.setProject(
                org.dependencytrack.proto.notification.v1.Project.newBuilder()
                        .setUuid(childProject.getUuid().toString())
                        .setName(childProject.getName())
                        .build());
        final Notification notification = notificationBuilder
                .setSubject(Any.pack(subjectBuilder.build()))
                .build();

        // Only the rule with "notify children" ENABLED should have matched.
        assertThat(router.route(List.of(notification))).satisfiesExactly(task -> {
            assertThat(task.ruleId()).isEqualTo(ruleNotifyChildren.getId());
            assertThat(task.ruleName()).isEqualTo(ruleNotifyChildren.getName());
            assertThat(task.notification()).isEqualTo(notification);
        });
    }

    @Test
    public void routeShouldMatchRulesWithMatchingProjectTags() throws Exception {
        final var tagA = qm.persist(new Tag("a"));
        final var tagB = qm.persist(new Tag("b"));

        // Create a project tagged with tag A.
        final var project = new Project();
        project.setName("acme-app");
        project.setTags(Set.of(tagA));
        qm.persist(project);

        // Create a rule limited to tag A.
        final var ruleTagA = new NotificationRule();
        ruleTagA.setName("A");
        ruleTagA.setScope(NotificationScope.PORTFOLIO);
        ruleTagA.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
        ruleTagA.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        ruleTagA.setEnabled(true);
        ruleTagA.setTags(Set.of(tagA));
        qm.persist(ruleTagA);

        // Create a rule limited to tag B.
        final var ruleTagB = new NotificationRule();
        ruleTagB.setName("B");
        ruleTagB.setScope(NotificationScope.PORTFOLIO);
        ruleTagB.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
        ruleTagB.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        ruleTagB.setEnabled(true);
        ruleTagB.setTags(Set.of(tagB));
        qm.persist(ruleTagB);

        // Create a notification for the project tagged with tag A.
        final Notification.Builder notificationBuilder =
                TestNotificationFactory.createBomConsumedTestNotification().toBuilder();
        final BomConsumedOrProcessedSubject.Builder subjectBuilder =
                notificationBuilder.getSubject().unpack(BomConsumedOrProcessedSubject.class).toBuilder();
        subjectBuilder.setProject(
                org.dependencytrack.proto.notification.v1.Project.newBuilder()
                        .setUuid(project.getUuid().toString())
                        .setName(project.getName())
                        .addTags(tagA.getName())
                        .build());
        final Notification notification = notificationBuilder
                .setSubject(Any.pack(subjectBuilder.build()))
                .build();

        // Only the rule limited to tag A must have matched.
        assertThat(router.route(List.of(notification))).satisfiesExactly(task -> {
            assertThat(task.ruleId()).isEqualTo(ruleTagA.getId());
            assertThat(task.ruleName()).isEqualTo(ruleTagA.getName());
            assertThat(task.notification()).isEqualTo(notification);
        });
    }

    @Test
    public void routeShouldMatchMultipleRules() {
        final var ruleA = new NotificationRule();
        ruleA.setName("A");
        ruleA.setScope(NotificationScope.PORTFOLIO);
        ruleA.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
        ruleA.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        ruleA.setEnabled(true);
        qm.persist(ruleA);

        final var ruleB = new NotificationRule();
        ruleB.setName("B");
        ruleB.setScope(NotificationScope.PORTFOLIO);
        ruleB.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
        ruleB.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        ruleB.setEnabled(true);
        qm.persist(ruleB);

        final Notification notification = TestNotificationFactory.createBomConsumedTestNotification();

        assertThat(router.route(List.of(notification))).satisfiesExactlyInAnyOrder(
                task -> {
                    assertThat(task.ruleId()).isEqualTo(ruleA.getId());
                    assertThat(task.ruleName()).isEqualTo(ruleA.getName());
                    assertThat(task.notification()).isEqualTo(notification);
                },
                task -> {
                    assertThat(task.ruleId()).isEqualTo(ruleB.getId());
                    assertThat(task.ruleName()).isEqualTo(ruleB.getName());
                    assertThat(task.notification()).isEqualTo(notification);
                });
    }

    @SuppressWarnings("unused")
    private List<Notification> routeShouldHandleAllNotificationTypesParams() {
        final var notifications = new ArrayList<Notification>();

        for (final NotificationScope scope : NotificationScope.values()) {
            for (final NotificationGroup group : NotificationGroup.values()) {
                for (final NotificationLevel level : NotificationLevel.values()) {
                    final Notification notification = TestNotificationFactory.createTestNotification(scope, group, level);
                    if (notification != null) {
                        notifications.add(notification);
                    }
                }
            }
        }

        return notifications;
    }

    @Test
    @Parameters(method = "routeShouldHandleAllNotificationTypesParams")
    public void routeShouldHandleAllNotificationTypes(final Notification notification) {
        final var rule = new NotificationRule();
        rule.setName("foo");
        rule.setScope(convert(notification.getScope()));
        rule.setNotifyOn(Set.of(convert(notification.getGroup())));
        rule.setNotificationLevel(convert(notification.getLevel()));
        rule.setEnabled(true);
        qm.persist(rule);

        assertThat(router.route(List.of(notification))).satisfiesExactly(task -> {
            assertThat(task.ruleId()).isEqualTo(rule.getId());
            assertThat(task.ruleName()).isEqualTo(rule.getName());
            assertThat(task.notification()).isEqualTo(notification);
        });
    }

}