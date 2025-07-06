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
package org.dependencytrack.search;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.search.SearchExpressionEvaluator.EvaluationResult;
import org.junit.Before;
import org.junit.Test;
import org.projectnessie.cel.Env;
import org.projectnessie.cel.EnvOption;
import org.projectnessie.cel.checker.Checker;
import org.projectnessie.cel.checker.Decls;
import org.projectnessie.cel.common.types.pb.ProtoTypeRegistry;

import javax.jdo.Query;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class SearchExpressionEvaluatorTest extends PersistenceCapableTest {

    private SearchExpressionEvaluator evaluator;

    @Before
    public void before() throws Exception {
        super.before();

        final Env env = Env.newCustomEnv(
                ProtoTypeRegistry.newRegistry(),
                List.of(
                        EnvOption.declarations(
                                Decls.newVar("group", Decls.String),
                                Decls.newVar("name", Decls.String),
                                Decls.newVar("version", Decls.String),
                                Decls.newVar("internal", Decls.Bool),
                                Decls.newVar("cpe", Decls.String),
                                Decls.newVar("purl", Decls.String)),
                        EnvOption.declarations(Checker.StandardDeclarations),
                        EnvOption.types(Component.getDefaultInstance())));

        final Map<String, String> fieldMappings = Map.ofEntries(
                Map.entry("group", "\"GROUP\""),
                Map.entry("name", "\"NAME\""),
                Map.entry("version", "\"VERSION\""),
                Map.entry("internal", "\"INTERNAL\""),
                Map.entry("cpe", "\"CPE\""),
                Map.entry("purl", "\"PURL\""));

        evaluator = new SearchExpressionEvaluator(env, fieldMappings);
    }

    @Test
    public void test() {
        final EvaluationResult result = evaluator.evaluate("""
                name == "foo" && version == "2.0" || !internal && cpe == null
                """);

        assertThat(result.sqlCondition()).isEqualToIgnoringWhitespace("""
                "NAME" = :param0 AND "VERSION" = :param1 OR NOT "INTERNAL" AND "CPE" IS NULL
                """);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new org.dependencytrack.model.Component();
        component.setProject(project);
        component.setName("foo");
        component.setVersion("2.0");
        qm.persist(component);

        final Query<?> query = qm.getPersistenceManager().newQuery(Query.SQL, """
                SELECT "ID" FROM "COMPONENT" WHERE %s
                """.formatted(result.sqlCondition()));
        query.setNamedParameters(result.queryParams());

        final long componentId = query.executeResultUnique(Long.class);
        assertThat(componentId).isEqualTo(component.getId());
    }

}