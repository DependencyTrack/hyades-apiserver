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
package org.dependencytrack.persistence.jdbi;

import alpine.persistence.OrderDirection;
import alpine.resources.AlpineRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.Ordering;
import org.dependencytrack.persistence.jdbi.ApiRequestConfig.OrderingColumn;
import org.jdbi.v3.core.qualifier.QualifiedType;
import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.core.statement.StatementCustomizer;

import javax.jdo.Query;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Map;
import java.util.Set;

import static org.dependencytrack.model.ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_API_FILTER_PARAMETER;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_API_OFFSET_LIMIT_CLAUSE;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_API_ORDER_BY_CLAUSE;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_API_PROJECT_ACL_CONDITION;
import static org.dependencytrack.util.PrincipalUtil.getPrincipalTeamIds;
import static org.jdbi.v3.core.generic.GenericTypes.parameterizeClass;

/**
 * A {@link StatementCustomizer} that enriches the {@link StatementContext}
 * with attributes and parameter bindings for:
 * <ul>
 *     <li>filtering: {@value JdbiAttributes#ATTRIBUTE_API_FILTER_PARAMETER}</li>
 *     <li>pagination: {@value JdbiAttributes#ATTRIBUTE_API_OFFSET_LIMIT_CLAUSE}</li>
 *     <li>ordering: {@value JdbiAttributes#ATTRIBUTE_API_ORDER_BY_CLAUSE}</li>
 *     <li>portfolio access control: {@value JdbiAttributes#ATTRIBUTE_API_PROJECT_ACL_CONDITION}</li>
 * </ul>
 * based on a provided {@link AlpineRequest}.
 * <p>
 * The functionality provided by this customizer is equivalent to these JDO counterparts:
 * <ul>
 *     <li>{@link org.dependencytrack.persistence.QueryManager#decorate(Query)}</li>
 *     <li>{@link org.dependencytrack.persistence.ComponentQueryManager#preprocessACLs(Query, String, Map, boolean)}</li>
 *     <li>{@link org.dependencytrack.persistence.ProjectQueryManager#preprocessACLs(Query, String, Map, boolean)}</li>
 * </ul>
 *
 * @since 5.5.0
 */
class ApiRequestStatementCustomizer implements StatementCustomizer {

    static final String PARAMETER_PROJECT_ACL_TEAM_IDS = "projectAclTeamIds";
    static final String TEMPLATE_PROJECT_ACL_CONDITION = "HAS_PROJECT_ACCESS(%s, :projectAclTeamIds)";

    private final AlpineRequest apiRequest;

    ApiRequestStatementCustomizer(final AlpineRequest apiRequest) {
        this.apiRequest = apiRequest;
    }

    @Override
    public void beforeTemplating(final PreparedStatement stmt, final StatementContext ctx) throws SQLException {
        defineFilter(ctx);
        defineOrdering(ctx);
        definePagination(ctx);
        defineProjectAclCondition(ctx);
    }

    private void defineFilter(final StatementContext ctx) {
        if (apiRequest == null || apiRequest.getFilter() == null) {
            return;
        }

        ctx.define(ATTRIBUTE_API_FILTER_PARAMETER, ":apiFilter");
        ctx.getBinding().addNamed("apiFilter", apiRequest.getFilter());
    }

    private void defineOrdering(final StatementContext ctx) {
        if (apiRequest == null) {
            return;
        }

        final var ordering = new Ordering(apiRequest);
        final var orderingBuilder = new StringBuilder();
        final var config = ctx.getConfig(ApiRequestConfig.class);

        if (apiRequest.getOrderBy() != null) {
            if (config.orderingAllowedColumns() == null) {
                return;
            }
            if (config.orderingAllowedColumns().isEmpty()) {
                throw new IllegalArgumentException("Ordering is not allowed");
            }
            final OrderingColumn orderingColumn = config.orderingAllowedColumn(ordering.by())
                    .orElseThrow(() -> new IllegalArgumentException("Ordering by column %s is not allowed; Allowed columns are: %s"
                            .formatted(ordering.by(), config.orderingAllowedColumns().stream().map(OrderingColumn::name).toList())));

            orderingBuilder.append("ORDER BY ");
            if (orderingColumn.queryName() == null) {
                orderingBuilder
                        .append("\"")
                        .append(ordering.by())
                        .append("\"");
            } else {
                orderingBuilder.append(orderingColumn.queryName());
            }

            if (ordering.direction() != null && ordering.direction() != OrderDirection.UNSPECIFIED) {
                orderingBuilder
                        .append(" ")
                        .append(ordering.direction() == OrderDirection.ASCENDING ? "ASC" : "DESC");
            }
        }

        if (!config.orderingAlwaysBy().isBlank() && (ordering.by() == null || !ordering.by().equals(config.orderingAlwaysBy()))) {
            final String[] alwaysByParts = config.orderingAlwaysBy().split("\\s");
            if (alwaysByParts.length > 2) {
                throw new IllegalArgumentException("alwaysBy must consist of no more than two parts");
            }

            final OrderingColumn orderingColumnAlwaysBy = config.orderingAllowedColumn(alwaysByParts[0])
                    .orElseThrow(() -> new IllegalArgumentException("Ordering by column %s is not allowed; Allowed columns are: %s"
                            .formatted(alwaysByParts[0], config.orderingAllowedColumns().stream().map(OrderingColumn::name).toList())));

            if (orderingColumnAlwaysBy.queryName() == null) {
                orderingBuilder
                        .append(orderingBuilder.isEmpty() ? "ORDER BY \"" : ", \"")
                        .append(orderingColumnAlwaysBy.name())
                        .append("\"");
            } else {
                orderingBuilder
                        .append(orderingBuilder.isEmpty() ? "ORDER BY " : ", ")
                        .append(orderingColumnAlwaysBy.queryName());
            }

            if (alwaysByParts.length == 2
                && ("asc".equalsIgnoreCase(alwaysByParts[1]) || "desc".equalsIgnoreCase(alwaysByParts[1]))) {
                orderingBuilder
                        .append(" ")
                        .append(alwaysByParts[1]);
            }
        }

        if (!orderingBuilder.isEmpty()) {
            ctx.define(ATTRIBUTE_API_ORDER_BY_CLAUSE, orderingBuilder.toString());
        }
    }

    private void definePagination(final StatementContext ctx) {
        if (apiRequest != null
            && apiRequest.getPagination() != null
            && apiRequest.getPagination().isPaginated()) {
            ctx.define(ATTRIBUTE_API_OFFSET_LIMIT_CLAUSE, "OFFSET :paginationOffset FETCH NEXT :paginationLimit ROWS ONLY");
            ctx.getBinding().addNamed("paginationOffset", apiRequest.getPagination().getOffset());
            ctx.getBinding().addNamed("paginationLimit", apiRequest.getPagination().getLimit());
        }
    }

    private void defineProjectAclCondition(final StatementContext ctx) throws SQLException {
        if (apiRequest == null
            || apiRequest.getPrincipal() == null
            || !isAclEnabled(ctx)
            || apiRequest.getEffectivePermissions().contains(Permissions.ACCESS_MANAGEMENT.name())) {
            ctx.define(ATTRIBUTE_API_PROJECT_ACL_CONDITION, "TRUE");
            return;
        }

        final Set<Long> principalTeamIds = getPrincipalTeamIds(apiRequest.getPrincipal());
        if (principalTeamIds.isEmpty()) {
            ctx.define(ATTRIBUTE_API_PROJECT_ACL_CONDITION, "FALSE");
            return;
        }

        final ApiRequestConfig config = ctx.getConfig(ApiRequestConfig.class);

        ctx.define(
                ATTRIBUTE_API_PROJECT_ACL_CONDITION,
                TEMPLATE_PROJECT_ACL_CONDITION.formatted(config.projectAclProjectIdColumn())
        );
        ctx.getBinding().addNamed(PARAMETER_PROJECT_ACL_TEAM_IDS, principalTeamIds,
                QualifiedType.of(parameterizeClass(Set.class, Long.class)));
    }

    private boolean isAclEnabled(final StatementContext ctx) throws SQLException {
        try (final PreparedStatement ps = ctx.getConnection().prepareStatement("""
                SELECT 1
                  FROM "CONFIGPROPERTY"
                 WHERE "GROUPNAME" = ?
                   AND "PROPERTYNAME" = ?
                   AND "PROPERTYVALUE" = 'true'
                """)) {
            ps.setString(1, ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName());
            ps.setString(2, ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName());
            return ps.executeQuery().next();
        }
    }

}
