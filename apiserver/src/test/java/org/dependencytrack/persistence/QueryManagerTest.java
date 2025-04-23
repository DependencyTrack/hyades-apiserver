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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentMetaInformation;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityAnalysis;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.Project;

import org.junit.Test;

import alpine.model.Permission;
import alpine.model.Team;
import alpine.model.UserPrincipal;
import alpine.server.auth.PasswordService;

import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.BiFunction;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_PASSED;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_UNKNOWN;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class QueryManagerTest extends PersistenceCapableTest {
    @Test
    public void testGetMetaInformation() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        //add another component for better testing
        Component component2 = new Component();
        component2.setProject(project);
        component2.setName("ABC");
        component2.setPurl("pkg:maven/org.acme/abc");

        IntegrityAnalysis integrityAnalysis = new IntegrityAnalysis();
        integrityAnalysis.setComponent(component);
        integrityAnalysis.setIntegrityCheckStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        Date published = new Date();
        integrityAnalysis.setUpdatedAt(published);
        integrityAnalysis.setId(component.getId());
        integrityAnalysis.setMd5HashMatchStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        integrityAnalysis.setSha1HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha256HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha512HashMatchStatus(HASH_MATCH_PASSED);
        qm.persist(integrityAnalysis);
        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setPublishedAt(published);
        integrityMetaComponent.setLastFetch(published);
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setRepositoryUrl("repo.url.com");
        qm.createIntegrityMetaComponent(integrityMetaComponent);
        component = qm.createComponent(component, false);
        ComponentMetaInformation componentMetaInformation = qm.getMetaInformation(component.getUuid());
        assertEquals(HASH_MATCH_PASSED, componentMetaInformation.integrityMatchStatus());
        assertEquals(integrityMetaComponent.getPublishedAt(), componentMetaInformation.publishedDate());
        assertEquals(integrityMetaComponent.getLastFetch(), componentMetaInformation.lastFetched());
        assertEquals(integrityMetaComponent.getRepositoryUrl(), componentMetaInformation.integrityRepoUrl());
    }

    @Test
    public void testGetMetaInformationWhenPublishedAtIsMissing() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        IntegrityAnalysis integrityAnalysis = new IntegrityAnalysis();
        integrityAnalysis.setComponent(component);
        integrityAnalysis.setIntegrityCheckStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        integrityAnalysis.setUpdatedAt(new Date());
        integrityAnalysis.setId(component.getId());
        integrityAnalysis.setMd5HashMatchStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        integrityAnalysis.setSha1HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha256HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha512HashMatchStatus(HASH_MATCH_PASSED);
        qm.persist(integrityAnalysis);
        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        qm.createIntegrityMetaComponent(integrityMetaComponent);
        component = qm.createComponent(component, false);
        ComponentMetaInformation componentMetaInformation = qm.getMetaInformation(component.getUuid());
        assertEquals(HASH_MATCH_PASSED, componentMetaInformation.integrityMatchStatus());
        assertNull(componentMetaInformation.publishedDate());
        assertNull(componentMetaInformation.lastFetched());
    }

    @Test
    public void testGetMetaInformationWhenIntregrityAnalysisIsMissing() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        qm.createIntegrityMetaComponent(integrityMetaComponent);
        component = qm.createComponent(component, false);
        ComponentMetaInformation componentMetaInformation = qm.getMetaInformation(component.getUuid());
        assertNull(componentMetaInformation.publishedDate());
        assertNull(componentMetaInformation.lastFetched());
    }

    @Test
    public void tryAcquireAdvisoryLockShouldReturnTrueWhenAcquired() {
        qm.runInTransaction(() -> assertThat(qm.tryAcquireAdvisoryLock("foo")).isTrue());
    }

    @Test
    public void tryAcquireAdvisoryLockShouldReturnFalseWhenNotAcquired() throws Exception {
        try (final ExecutorService executorService = Executors.newFixedThreadPool(2)) {
            final var startLatch = new CountDownLatch(1);
            final var firstLockLatch = new CountDownLatch(1);
            final var secondLockLatch = new CountDownLatch(1);

            final Future<Boolean> firstLockAcquiredFuture = executorService.submit(() -> {
                startLatch.await();

                try (final var qm = new QueryManager()) {
                    return qm.callInTransaction(() -> {
                        final boolean acquired = qm.tryAcquireAdvisoryLock("foo");

                        // Hold the lock until the second lock attempt completed.
                        firstLockLatch.countDown();
                        secondLockLatch.await();

                        return acquired;
                    });
                }
            });

            final Future<Boolean> secondLockAcquiredFuture = executorService.submit(() -> {
                // Wait for first lock attempt to complete.
                firstLockLatch.await();

                try (final var qm = new QueryManager()) {
                    return qm.callInTransaction(() -> {
                        final boolean acquired = qm.tryAcquireAdvisoryLock("foo");
                        secondLockLatch.countDown();
                        return acquired;
                    });

                }
            });

            startLatch.countDown();

            assertThat(firstLockAcquiredFuture.get()).isTrue();
            assertThat(secondLockAcquiredFuture.get()).isFalse();
        }
    }

    @Test
    public void tryAcquireAdvisoryLockShouldThrowWhenNoActiveTransaction() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> qm.tryAcquireAdvisoryLock("foo"))
                .withMessage("Advisory lock can only be acquired in a transaction");
    }

    @Test
    public void testGetEffectivePermissions() {
        var ldapUser = qm.createLdapUser("ldapuser");
        var mgdUser = qm.createManagedUser("mgduser", "mgduser", "mgduser@localhost",
                new String(PasswordService.createHash("mgduser".toCharArray())), true, false, false);
        var oidcUser = qm.createOidcUser("oidcuser");

        BiFunction<String, List<Permissions>, Team> teamCreator = (name, permissions) -> {
            return qm.callInTransaction(() -> {
                var team = qm.createTeam(name);
                team.setPermissions(permissions.stream()
                        .map(permission -> qm.createPermission(permission.name(), permission.getDescription()))
                        .toList());

                return qm.persist(team);
            });
        };

        var team1 = teamCreator.apply("Effective Permissions Test Team 1", List.of(
                Permissions.PORTFOLIO_MANAGEMENT,
                Permissions.VULNERABILITY_ANALYSIS,
                Permissions.VULNERABILITY_MANAGEMENT,
                Permissions.ACCESS_MANAGEMENT,
                Permissions.SYSTEM_CONFIGURATION,
                Permissions.POLICY_MANAGEMENT));

        var team2 = teamCreator.apply("Effective Permissions Test Team 2", List.of(
                Permissions.VIEW_PORTFOLIO,
                Permissions.VIEW_VULNERABILITY,
                Permissions.VIEW_POLICY_VIOLATION,
                Permissions.VIEW_BADGES));

        var team3 = teamCreator.apply("Effective Permissions Test Team 3", List.of(
                Permissions.PORTFOLIO_MANAGEMENT_UPDATE,
                Permissions.VULNERABILITY_ANALYSIS_UPDATE,
                Permissions.VULNERABILITY_MANAGEMENT_UPDATE,
                Permissions.ACCESS_MANAGEMENT_UPDATE,
                Permissions.SYSTEM_CONFIGURATION_UPDATE,
                Permissions.POLICY_MANAGEMENT_UPDATE));

        var noAccessTeam = teamCreator.apply("Effective Permissions Test with No Access", List.of(
                Permissions.BOM_UPLOAD,
                Permissions.PROJECT_CREATION_UPLOAD));

        qm.addUserToTeam(ldapUser, team1);
        qm.addUserToTeam(mgdUser, team2);
        qm.addUserToTeam(oidcUser, team3);

        // Add all users to a team with no entry in PROJECT_ACCESS_TEAMS having
        // permissions that should not be present during assertion
        qm.addUserToTeam(ldapUser, noAccessTeam);
        qm.addUserToTeam(mgdUser, noAccessTeam);
        qm.addUserToTeam(oidcUser, noAccessTeam);

        BiFunction<String, String, Project> projectCreator = (name, version) -> {
            return qm.callInTransaction(() -> {
                var project = new Project();
                project.setName(name);
                project.setDescription("Project for testing effective permissions");
                project.setVersion(version);
                project.setActive(true);
                project.setIsLatest(true);

                return qm.persist(project);
            });
        };

        var project1 = projectCreator.apply("test-project-1", "v0.1.0");
        var project2 = projectCreator.apply("test-project-2", "v0.1.1");
        var project3 = projectCreator.apply("test-project-3", "v0.1.2");

        project1.addAccessTeam(team1);
        qm.persist(project1);
        project2.addAccessTeam(team2);
        qm.persist(project2);
        project3.addAccessTeam(team3);
        qm.persist(project3);

        Function<List<Permission>, String[]> getPermissionNames = permissions -> permissions
                .stream()
                .map(Permission::getName)
                .toArray(String[]::new);

        record TestMatrixEntry(UserPrincipal user, Project project, Team team, List<Project> noAccessProjects) {
            String[] getPermissionNames(List<Permission> permissions) {
                return permissions
                        .stream()
                        .map(Permission::getName)
                        .toArray(String[]::new);
            }
        }

        var permission = qm.createPermission(
                Permissions.POLICY_VIOLATION_ANALYSIS.name(),
                Permissions.POLICY_VIOLATION_ANALYSIS.getDescription());

        for (var entry : new TestMatrixEntry[] {
                new TestMatrixEntry(ldapUser, project1, team1, List.of(project2, project3)),
                new TestMatrixEntry(mgdUser, project2, team2, List.of(project1, project3)),
                new TestMatrixEntry(oidcUser, project3, team3, List.of(project1, project2))
        }) {
            assertThat(entry.getPermissionNames(qm.getEffectivePermissions(entry.user(), entry.project())))
                    .containsExactlyInAnyOrder(entry.getPermissionNames(entry.team().getPermissions()));

            for (var project : entry.noAccessProjects())
                assertThat(entry.getPermissionNames(qm.getEffectivePermissions(entry.user(), project))).isEmpty();

            assertThat(entry.getPermissionNames(qm.getEffectivePermissions(entry.user(), entry.project())))
                    .doesNotContain(getPermissionNames.apply(noAccessTeam.getPermissions()));

            // Add a permission to team and verify effective permissions are updated accordingly
            qm.runInTransaction(() -> {
                var team = qm.getObjectByUuid(Team.class, entry.team().getUuid());
                team.getPermissions().add(permission);
                qm.persist(team);
            });

            assertThat(entry.getPermissionNames(qm.getEffectivePermissions(entry.user(), entry.project())))
                    .contains(Permissions.POLICY_VIOLATION_ANALYSIS.name());
        }
    }

}
