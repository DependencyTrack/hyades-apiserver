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

import alpine.model.ApiKey;
import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.persistence.OrderDirection;
import alpine.resources.AlpineRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.Ordering;
import org.dependencytrack.persistence.jdbi.ApiRequestConfig.OrderingColumn;
import org.jdbi.v3.core.qualifier.QualifiedType;
import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.core.statement.StatementCustomizer;

import javax.jdo.Query;
import java.security.Principal;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
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
@SuppressWarnings("JavadocReference")
class ApiRequestStatementCustomizer implements StatementCustomizer {

    static final String PARAMETER_PROJECT_ACL_TEAM_IDS = "projectAclTeamIds";
    static final String TEMPLATE_PROJECT_ACL_CONDITION = "HAS_PROJECT_ACCESS(\"%s\".\"ID\", :projectAclTeamIds)";

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
        if (apiRequest == null || apiRequest.getOrderBy() == null) {
            return;
        }

        final var config = ctx.getConfig(ApiRequestConfig.class);
        if (config.orderingAllowedColumns().isEmpty()) {
            throw new IllegalArgumentException("Ordering is not allowed");
        }

        final var ordering = new Ordering(apiRequest);
        final OrderingColumn orderingColumn = config.orderingAllowedColumn(ordering.by())
                .orElseThrow(() -> new IllegalArgumentException("Ordering by column %s is not allowed; Allowed columns are: %s"
                        .formatted(ordering.by(), config.orderingAllowedColumns().stream().map(OrderingColumn::name).toList())));

        final var orderingBuilder = new StringBuilder("ORDER BY ");
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

        if (!config.orderingAlwaysBy().isBlank() && !ordering.by().equals(config.orderingAlwaysBy())) {
            final String[] alwaysByParts = config.orderingAlwaysBy().split("\\s");
            if (alwaysByParts.length > 2) {
                throw new IllegalArgumentException("alwaysBy must consist of no more than two parts");
            }

            final OrderingColumn orderingColumnAlwaysBy = config.orderingAllowedColumn(alwaysByParts[0])
                    .orElseThrow(() -> new IllegalArgumentException("Ordering by column %s is not allowed; Allowed columns are: %s"
                            .formatted(alwaysByParts[0], config.orderingAllowedColumns().stream().map(OrderingColumn::name).toList())));
            if (orderingColumnAlwaysBy.queryName() == null) {
                orderingBuilder
                        .append(", \"")
                        .append(orderingColumnAlwaysBy.name())
                        .append("\"");
            } else {
                orderingBuilder.append(orderingColumnAlwaysBy.queryName());
            }

            if (alwaysByParts.length == 2
                && ("asc".equalsIgnoreCase(alwaysByParts[1]) || "desc".equalsIgnoreCase(alwaysByParts[1]))) {
                orderingBuilder
                        .append(" ")
                        .append(alwaysByParts[1]);
            }
        }

        ctx.define(ATTRIBUTE_API_ORDER_BY_CLAUSE, orderingBuilder.toString());
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
        if (apiRequest == null) {
            return;
        }

        if (apiRequest.getPrincipal() == null
            || !isAclEnabled(ctx)
            || hasAccessManagementPermission(ctx, apiRequest.getPrincipal())) {
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
                TEMPLATE_PROJECT_ACL_CONDITION.formatted(config.projectAclProjectTableName())
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

    private boolean hasAccessManagementPermission(final StatementContext ctx, final Principal principal) throws SQLException {
        // TODO: After upgrading to Alpine >= 3.2.0, this should become:
        //   apiRequest.getEffectivePermission().contains(Permissions.ACCESS_MANAGEMENT.name())
        // https://github.com/stevespringett/Alpine/pull/764

        return switch (principal) {
            case ApiKey apiKey -> hasAccessManagementPermission(ctx, apiKey);
            case LdapUser ldapUser -> hasAccessManagementPermission(ctx, ldapUser);
            case ManagedUser managedUser -> hasAccessManagementPermission(ctx, managedUser);
            case OidcUser oidcUser -> hasAccessManagementPermission(ctx, oidcUser);
            default -> false;
        };
    }

    private boolean hasAccessManagementPermission(final StatementContext ctx, final ApiKey apiKey) throws SQLException {
        try (final PreparedStatement ps = ctx.getConnection().prepareStatement("""
                SELECT EXISTS(
                  SELECT 1
                    FROM "APIKEY"
                   INNER JOIN "APIKEYS_TEAMS"
                      ON "APIKEYS_TEAMS"."APIKEY_ID" = "APIKEY"."ID"
                   INNER JOIN "TEAM"
                      ON "TEAM"."ID" = "APIKEYS_TEAMS"."TEAM_ID"
                   INNER JOIN "TEAMS_PERMISSIONS"
                      ON "TEAMS_PERMISSIONS"."TEAM_ID" = "TEAM"."ID"
                   INNER JOIN "PERMISSION"
                      ON "PERMISSION"."ID" = "TEAMS_PERMISSIONS"."PERMISSION_ID"
                   WHERE "APIKEY"."ID" = ?
                     AND "PERMISSION"."NAME" = ?
                )""")) {
            ps.setLong(1, apiKey.getId());
            ps.setString(2, Permissions.Constants.ACCESS_MANAGEMENT);

            final ResultSet rs = ps.executeQuery();
            return rs.next() && rs.getBoolean(1);
        }
    }

    private boolean hasAccessManagementPermission(final StatementContext ctx, final LdapUser user) throws SQLException {
        try (final PreparedStatement ps = ctx.getConnection().prepareStatement("""
                SELECT EXISTS(
                  SELECT 1
                    FROM "LDAPUSER"
                   INNER JOIN "LDAPUSERS_TEAMS"
                      ON "LDAPUSERS_TEAMS"."LDAPUSER_ID" = "LDAPUSER"."ID"
                   INNER JOIN "TEAM"
                      ON "TEAM"."ID" = "LDAPUSERS_TEAMS"."TEAM_ID"
                   INNER JOIN "TEAMS_PERMISSIONS"
                      ON "TEAMS_PERMISSIONS"."TEAM_ID" = "TEAM"."ID"
                   INNER JOIN "PERMISSION"
                      ON "PERMISSION"."ID" = "TEAMS_PERMISSIONS"."PERMISSION_ID"
                   WHERE "LDAPUSER"."ID" = ?
                     AND "PERMISSION"."NAME" = ?
                   UNION
                  SELECT 1
                    FROM "LDAPUSER"
                   INNER JOIN "LDAPUSERS_PERMISSIONS"
                      ON "LDAPUSERS_PERMISSIONS"."LDAPUSER_ID" = "LDAPUSER"."ID"
                   INNER JOIN "PERMISSION"
                      ON "PERMISSION"."ID" = "LDAPUSERS_PERMISSIONS"."PERMISSION_ID"
                   WHERE "LDAPUSER"."ID" = ?
                     AND "PERMISSION"."NAME" = ?
                )""")) {
            ps.setLong(1, user.getId());
            ps.setString(2, Permissions.Constants.ACCESS_MANAGEMENT);
            ps.setLong(3, user.getId());
            ps.setString(4, Permissions.Constants.ACCESS_MANAGEMENT);

            final ResultSet rs = ps.executeQuery();
            return rs.next() && rs.getBoolean(1);
        }
    }

    private boolean hasAccessManagementPermission(final StatementContext ctx, final ManagedUser user) throws SQLException {
        try (final PreparedStatement ps = ctx.getConnection().prepareStatement("""
                SELECT EXISTS(
                  SELECT 1
                    FROM "MANAGEDUSER"
                   INNER JOIN "MANAGEDUSERS_TEAMS"
                      ON "MANAGEDUSERS_TEAMS"."MANAGEDUSER_ID" = "MANAGEDUSER"."ID"
                   INNER JOIN "TEAM"
                      ON "TEAM"."ID" = "MANAGEDUSERS_TEAMS"."TEAM_ID"
                   INNER JOIN "TEAMS_PERMISSIONS"
                      ON "TEAMS_PERMISSIONS"."TEAM_ID" = "TEAM"."ID"
                   INNER JOIN "PERMISSION"
                      ON "PERMISSION"."ID" = "TEAMS_PERMISSIONS"."PERMISSION_ID"
                   WHERE "MANAGEDUSER"."ID" = ?
                     AND "PERMISSION"."NAME" = ?
                   UNION
                  SELECT 1
                    FROM "MANAGEDUSER"
                   INNER JOIN "MANAGEDUSERS_PERMISSIONS"
                      ON "MANAGEDUSERS_PERMISSIONS"."MANAGEDUSER_ID" = "MANAGEDUSER"."ID"
                   INNER JOIN "PERMISSION"
                      ON "PERMISSION"."ID" = "MANAGEDUSERS_PERMISSIONS"."PERMISSION_ID"
                   WHERE "MANAGEDUSER"."ID" = ?
                     AND "PERMISSION"."NAME" = ?
                )""")) {
            ps.setLong(1, user.getId());
            ps.setString(2, Permissions.Constants.ACCESS_MANAGEMENT);
            ps.setLong(3, user.getId());
            ps.setString(4, Permissions.Constants.ACCESS_MANAGEMENT);

            final ResultSet rs = ps.executeQuery();
            return rs.next() && rs.getBoolean(1);
        }
    }

    private boolean hasAccessManagementPermission(final StatementContext ctx, final OidcUser user) throws SQLException {
        try (final PreparedStatement ps = ctx.getConnection().prepareStatement("""
                SELECT EXISTS(
                  SELECT 1
                    FROM "OIDCUSER"
                   INNER JOIN "OIDCUSERS_TEAMS"
                      ON "OIDCUSERS_TEAMS"."OIDCUSERS_ID" = "OIDCUSER"."ID"
                   INNER JOIN "TEAM"
                      ON "TEAM"."ID" = "OIDCUSERS_TEAMS"."TEAM_ID"
                   INNER JOIN "TEAMS_PERMISSIONS"
                      ON "TEAMS_PERMISSIONS"."TEAM_ID" = "TEAM"."ID"
                   INNER JOIN "PERMISSION"
                      ON "PERMISSION"."ID" = "TEAMS_PERMISSIONS"."PERMISSION_ID"
                   WHERE "OIDCUSER"."ID" = ?
                     AND "PERMISSION"."NAME" = ?
                   UNION
                  SELECT 1
                    FROM "OIDCUSER"
                   INNER JOIN "OIDCUSERS_PERMISSIONS"
                      ON "OIDCUSERS_PERMISSIONS"."OIDCUSER_ID" = "OIDCUSER"."ID"
                   INNER JOIN "PERMISSION"
                      ON "PERMISSION"."ID" = "OIDCUSERS_PERMISSIONS"."PERMISSION_ID"
                   WHERE "OIDCUSER"."ID" = ?
                     AND "PERMISSION"."NAME" = ?
                )""")) {
            ps.setLong(1, user.getId());
            ps.setString(2, Permissions.Constants.ACCESS_MANAGEMENT);
            ps.setLong(3, user.getId());
            ps.setString(4, Permissions.Constants.ACCESS_MANAGEMENT);

            final ResultSet rs = ps.executeQuery();
            return rs.next() && rs.getBoolean(1);
        }
    }

}
