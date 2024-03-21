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
import org.apache.commons.lang3.ArrayUtils;
import org.dependencytrack.persistence.Ordering;
import org.jdbi.v3.sqlobject.customizer.SqlStatementCustomizerFactory;
import org.jdbi.v3.sqlobject.customizer.SqlStatementCustomizingAnnotation;
import org.jdbi.v3.sqlobject.customizer.SqlStatementParameterCustomizer;

import java.lang.annotation.Annotation;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.lang.reflect.Type;

/**
 * Defines an {@code ordering} template variable according to the annotated {@link Ordering} parameter.
 * <p>
 * An {@link Ordering} initialized as {@code new Ordering("foo", OrderDirection.DESCENDING)} will result
 * in the {@code ordering} variable to be defined as {@code ORDER BY "foo" DESC}.
 * <p>
 * If the annotated {@link Ordering} is {@code null}, or {@link Ordering#by()} is blank,
 * the {@code ordering} variable will <strong>not</strong> be defined.
 * It's recommended to use FreeMarker's default operator ({@code !}) to deal with this, for example:
 * {@code SELECT "FOO" FROM "BAR" ${ordering!}}
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
@SqlStatementCustomizingAnnotation(DefineOrdering.StatementCustomizerFactory.class)
public @interface DefineOrdering {

    /**
     * Column names that can be used for ordering.
     * <p>
     * Providing {@link Ordering#by()} values other than the ones defined here
     * will cause an {@link IllegalArgumentException} to be thrown.
     */
    String[] allowedColumns();

    /**
     * When {@link Ordering#by()} is provided, additionally order by this column name.
     * <p>
     * Expected format is {@code <columnName> [<direction>]}, for example {@code id ASC}.
     * {@code columnName} must be whitelisted via {@link #allowedColumns()}.
     * <p>
     * Useful when duplicate rows exist, but consistent ordering is desired.
     * In such cases, specifying an {@code alsoBy} of {@code id ASC} can help.
     */
    String alsoBy() default "";

    final class StatementCustomizerFactory implements SqlStatementCustomizerFactory {

        @Override
        public SqlStatementParameterCustomizer createForParameter(final Annotation annotation, final Class<?> sqlObjectType,
                                                                  final Method method, final Parameter param, final int index,
                                                                  final Type paramType) {
            return (statement, argument) -> {
                if (!(argument instanceof final Ordering ordering) || ordering.by() == null) {
                    return;
                }

                final var bindOrdering = (DefineOrdering) annotation;
                if (!ArrayUtils.contains(bindOrdering.allowedColumns(), ordering.by())) {
                    throw new IllegalArgumentException("Ordering by column %s is not allowed; Allowed columns are: %s"
                            .formatted(ordering.by(), bindOrdering.allowedColumns()));
                }

                final var orderingBuilder = new StringBuilder("ORDER BY \"")
                        .append(ordering.by())
                        .append("\"");
                if (ordering.direction() != null && ordering.direction() != OrderDirection.UNSPECIFIED) {
                    orderingBuilder
                            .append(" ")
                            .append(ordering.direction() == OrderDirection.ASCENDING ? "ASC" : "DESC");
                }

                if (!bindOrdering.alsoBy().isBlank() && !ordering.by().equals(bindOrdering.alsoBy())) {
                    final String[] alsoByParts = bindOrdering.alsoBy().split("\\s");
                    if (alsoByParts.length > 2) {
                        throw new IllegalArgumentException("alsoBy must consist of no more than two parts");
                    }

                    if (ArrayUtils.contains(bindOrdering.allowedColumns(), alsoByParts[0])) {
                        orderingBuilder
                                .append(", ")
                                .append("\"")
                                .append(alsoByParts[0])
                                .append("\"");
                    } else {
                        throw new IllegalArgumentException("Ordering by column %s is not allowed; Allowed columns are: %s"
                                .formatted(alsoByParts[0], bindOrdering.allowedColumns()));
                    }

                    if (alsoByParts.length == 2
                            && ("asc".equalsIgnoreCase(alsoByParts[1]) || "desc".equalsIgnoreCase(alsoByParts[1]))) {
                        orderingBuilder
                                .append(" ")
                                .append(alsoByParts[1]);
                    }
                }

                statement.define("ordering", orderingBuilder.toString());
            };
        }
    }

}
