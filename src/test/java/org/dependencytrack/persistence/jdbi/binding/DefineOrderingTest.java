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
package org.dependencytrack.persistence.jdbi.binding;

import alpine.persistence.OrderDirection;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.Ordering;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.freemarker.FreemarkerEngine;
import org.jdbi.v3.sqlobject.SqlObjectPlugin;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.jdbi;

public class DefineOrderingTest extends PersistenceCapableTest {

    public interface TestDao {

        @SqlQuery("SELECT \"ID\" AS \"id\", \"NAME\" AS \"nameAlias\" FROM \"COMPONENT\" ${ordering!}")
        List<Component> getComponents(@DefineOrdering(allowedColumns = "nameAlias") Ordering ordering);

        @SqlQuery("SELECT \"ID\" AS \"id\", \"NAME\" AS \"nameAlias\" FROM \"COMPONENT\" ${ordering!}")
        List<Component> getComponentsWithOrderingAlsoById(@DefineOrdering(allowedColumns = {"id", "nameAlias"}, alsoBy = "id DESC") Ordering ordering);

    }

    private Jdbi jdbi;
    private Project project;
    private final Map<String, Long> componentIdsByName = new HashMap<>();

    @Before
    public void setUp() {
        jdbi = jdbi(qm)
                .installPlugin(new SqlObjectPlugin())
                .setTemplateEngine(FreemarkerEngine.instance())
                .registerRowMapper(Component.class, (rs, ctx) -> {
                    final var component = new Component();
                    component.setId(rs.getLong("id"));
                    component.setName(rs.getString("nameAlias"));
                    return component;
                });

        project = new Project();
        project.setName("project");
        qm.persist(project);

        for (int i = 0; i < 5; i++) {
            final var component = new Component();
            component.setProject(project);
            component.setName("component-" + i);
            qm.persist(component);

            componentIdsByName.put(component.getName(), component.getId());
        }
    }

    @Test
    public void testWithNullOrdering() {
        final List<Component> components = jdbi.withExtension(TestDao.class, dao -> dao.getComponents(null));
        assertThat(components).extracting(Component::getName).containsExactlyInAnyOrder(
                "component-0",
                "component-1",
                "component-2",
                "component-3",
                "component-4"
        );
    }

    @Test
    public void testWithDisallowedColumn() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> jdbi.useExtension(TestDao.class,
                        dao -> dao.getComponents(new Ordering("NAME", OrderDirection.ASCENDING))));
    }

    @Test
    public void testWithOrderDirectionAscending() {
        final List<Component> components = jdbi.withExtension(TestDao.class,
                dao -> dao.getComponents(new Ordering("nameAlias", OrderDirection.ASCENDING)));

        assertThat(components).extracting(Component::getName).containsExactly(
                "component-0",
                "component-1",
                "component-2",
                "component-3",
                "component-4"
        );
    }

    @Test
    public void testWithOrderDirectionDescending() {
        final List<Component> components = jdbi.withExtension(TestDao.class,
                dao -> dao.getComponents(new Ordering("nameAlias", OrderDirection.DESCENDING)));

        assertThat(components).extracting(Component::getName).containsExactly(
                "component-4",
                "component-3",
                "component-2",
                "component-1",
                "component-0"
        );
    }

    @Test
    public void testWithOrderDirectionUnspecified() {
        final List<Component> components = jdbi.withExtension(TestDao.class,
                dao -> dao.getComponents(new Ordering("nameAlias", OrderDirection.UNSPECIFIED)));

        assertThat(components).extracting(Component::getName).containsExactly(
                "component-0",
                "component-1",
                "component-2",
                "component-3",
                "component-4"
        );
    }

    @Test
    public void testWithOrderingAlsoBy() {
        final var duplicateComponentIdsByName = new HashMap<String, Long>();
        for (int i = 0; i < 2; i++) {
            final var component = new Component();
            component.setProject(project);
            component.setName("component-" + i);
            qm.persist(component);

            duplicateComponentIdsByName.put(component.getName(), component.getId());
        }
        assertThat(qm.getCount(Component.class)).isEqualTo(7);

        final List<Component> components = jdbi.withExtension(TestDao.class,
                dao -> dao.getComponentsWithOrderingAlsoById(new Ordering("nameAlias", OrderDirection.ASCENDING)));
        assertThat(components).satisfiesExactly(
                component -> {
                    assertThat(component.getId()).isEqualTo(duplicateComponentIdsByName.get("component-0"));
                    assertThat(component.getName()).isEqualTo("component-0");
                },
                component -> {
                    assertThat(component.getId()).isEqualTo(componentIdsByName.get("component-0"));
                    assertThat(component.getName()).isEqualTo("component-0");
                },
                component -> {
                    assertThat(component.getId()).isEqualTo(duplicateComponentIdsByName.get("component-1"));
                    assertThat(component.getName()).isEqualTo("component-1");
                },
                component -> {
                    assertThat(component.getId()).isEqualTo(componentIdsByName.get("component-1"));
                    assertThat(component.getName()).isEqualTo("component-1");
                },
                component -> {
                    assertThat(component.getId()).isEqualTo(componentIdsByName.get("component-2"));
                    assertThat(component.getName()).isEqualTo("component-2");
                },
                component -> {
                    assertThat(component.getId()).isEqualTo(componentIdsByName.get("component-3"));
                    assertThat(component.getName()).isEqualTo("component-3");
                },
                component -> {
                    assertThat(component.getId()).isEqualTo(componentIdsByName.get("component-4"));
                    assertThat(component.getName()).isEqualTo("component-4");
                }
        );
    }

}
