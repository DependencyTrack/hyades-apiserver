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
package org.dependencytrack.persistence.datanucleus.method;

import alpine.model.Team;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.junit.Test;

import javax.jdo.Query;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class ProjectIsAccessibleByMethodTest extends PersistenceCapableTest {

    @Test
    @SuppressWarnings("resource")
    public void shouldEvaluateToTrueWhenProjectIsAccessible() {
        final var teamA = new Team();
        teamA.setName("team-a");
        qm.persist(teamA);

        final var teamB = new Team();
        teamB.setName("team-b");
        qm.persist(teamB);

        final var project = new Project();
        project.setName("acme-app");
        project.setAccessTeams(List.of(teamA, teamB));
        qm.persist(project);

        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        query.setFilter("this.isAccessibleBy(:teamIds)");
        query.setNamedParameters(Map.of("teamIds", new Long[]{teamA.getId(), teamB.getId()}));

        final List<Project> projects = query.executeList();
        assertThat(projects).hasSize(1);
    }

    @Test
    @SuppressWarnings("resource")
    public void shouldEvaluateToTrueWhenProjectParentIsAccessible() {
        final var team = new Team();
        team.setName("team");
        qm.persist(team);

        final var parentProject = new Project();
        parentProject.setName("acme-app-parent");
        parentProject.setAccessTeams(List.of(team));
        qm.persist(parentProject);

        final var project = new Project();
        project.setParent(parentProject);
        project.setName("acme-app");
        qm.persist(project);

        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        query.setFilter("name == 'acme-app' && this.isAccessibleBy(:teamIds)");
        query.setNamedParameters(Map.of("teamIds", new Long[]{team.getId()}));

        final List<Project> projects = query.executeList();
        assertThat(projects).hasSize(1);
    }

    @Test
    @SuppressWarnings("resource")
    public void shouldEvaluateToTrueWhenProjectGrandParentIsAccessible() {
        final var team = new Team();
        team.setName("team");
        qm.persist(team);

        final var grandParentProject = new Project();
        grandParentProject.setName("acme-app-grand-parent");
        grandParentProject.setAccessTeams(List.of(team));
        qm.persist(grandParentProject);

        final var parentProject = new Project();
        parentProject.setParent(grandParentProject);
        parentProject.setName("acme-app-parent");
        qm.persist(parentProject);

        final var project = new Project();
        project.setParent(parentProject);
        project.setName("acme-app");
        qm.persist(project);

        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        query.setFilter("name == 'acme-app' && this.isAccessibleBy(:teamIds)");
        query.setNamedParameters(Map.of("teamIds", new Long[]{team.getId()}));

        final List<Project> projects = query.executeList();
        assertThat(projects).hasSize(1);
    }

    @Test
    @SuppressWarnings("resource")
    public void shouldEvaluateToFalseWhenProjectIsNotAccessible() {
        final var teamA = new Team();
        teamA.setName("team-a");
        qm.persist(teamA);

        final var teamB = new Team();
        teamB.setName("team-b");
        qm.persist(teamB);

        final var project = new Project();
        project.setName("acme-app");
        project.setAccessTeams(List.of(teamA));
        qm.persist(project);

        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        query.setFilter("this.isAccessibleBy(:teamIds)");
        query.setNamedParameters(Map.of("teamIds", new Long[]{teamB.getId()}));

        final List<Project> projects = query.executeList();
        assertThat(projects).isEmpty();
    }

    @Test
    @SuppressWarnings("resource")
    public void shouldEvaluateToFalseWhenOnlyChildProjectIsAccessible() {
        final var team = new Team();
        team.setName("team");
        qm.persist(team);

        final var parentProject = new Project();
        parentProject.setName("acme-app-parent");
        qm.persist(parentProject);

        final var project = new Project();
        project.setParent(parentProject);
        project.setName("acme-app");
        project.setAccessTeams(List.of(team));
        qm.persist(project);

        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        query.setFilter("name == 'acme-app-parent' && this.isAccessibleBy(:teamIds)");
        query.setNamedParameters(Map.of("teamIds", new Long[]{team.getId()}));

        final List<Project> projects = query.executeList();
        assertThat(projects).hasSize(0);
    }

    @Test
    @SuppressWarnings("resource")
    public void shouldBeAllowedOnProjectMembersOfNonProjectObjects() {
        final var team = new Team();
        team.setName("team");
        qm.persist(team);

        final var project = new Project();
        project.setName("acme-app");
        project.setAccessTeams(List.of(team));
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Query<Component> query = qm.getPersistenceManager().newQuery(Component.class);
        query.setFilter("project.isAccessibleBy(:teamIds)");
        query.setNamedParameters(Map.of("teamIds", new Long[]{team.getId()}));

        final List<Component> components = query.executeList();
        assertThat(components).hasSize(1);
    }

    @Test
    @SuppressWarnings("resource")
    public void shouldThrowWhenCalledOnNonProjectObject() {
        final Query<Component> query = qm.getPersistenceManager().newQuery(Component.class);
        query.setFilter("this.isAccessibleBy(:teamIds)");
        query.setParameters(Arrays.asList(1L, 2L, 3L));
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(query::execute)
                .withMessage("""
                        isAccessibleBy is only allowed for objects of type org.dependencytrack.model.Project, \
                        but was called on org.dependencytrack.model.Component""");
    }

    @Test
    @SuppressWarnings("resource")
    public void shouldThrowWhenNoArgs() {
        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        query.setFilter("this.isAccessibleBy()");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(query::execute)
                .withMessage("Expected exactly one argument, but got 0");
    }

    @Test
    @SuppressWarnings("resource")
    public void shouldThrowWhenArgIsOfUnexpectedType() {
        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        query.setFilter("this.isAccessibleBy(:teamIdsString)");
        query.setParameters("1, 2, 3");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(query::execute)
                .withMessage("""
                        Expected argument to be of type org.datanucleus.store.rdbms.sql.expression.ArrayLiteral, \
                        but got org.datanucleus.store.rdbms.sql.expression.ParameterLiteral""");
    }

    @Test
    @SuppressWarnings("resource")
    public void shouldThrowWhenArgIsOfUnexpectedArrayType() {
        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        query.setFilter("this.isAccessibleBy(:teamIdStrings)");
        query.setNamedParameters(Map.of("teamIdsStrings", new String[]{"1", "2", "3"}));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(query::execute)
                .withMessage("""
                        Expected argument to be of type org.datanucleus.store.rdbms.sql.expression.ArrayLiteral, \
                        but got org.datanucleus.store.rdbms.sql.expression.ParameterLiteral""");
    }

}