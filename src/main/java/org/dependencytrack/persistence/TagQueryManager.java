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

import alpine.common.logging.Logger;
import alpine.persistence.OrderDirection;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.stream.Stream;

public class TagQueryManager extends QueryManager implements IQueryManager {

    private static final Comparator<Tag> TAG_COMPARATOR = Comparator.comparingInt(
            (Tag tag) -> tag.getProjects().size()).reversed();

    private static final Logger LOGGER = Logger.getLogger(ProjectQueryManager.class);

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    TagQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    TagQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * @since 4.12.0
     */
    public record TagListRow(String name, long projectCount, long policyCount, long totalCount) {

        @SuppressWarnings("unused") // DataNucleus will use this for MSSQL.
        public TagListRow(String name, int projectCount, int policyCount, int totalCount) {
            this(name, (long) projectCount, (long) policyCount, (long) totalCount);
        }

    }

    /**
     * @since 4.12.0
     */
    @Override
    public List<TagListRow> getTags() {
        final Map.Entry<String, Map<String, Object>> projectAclConditionAndParams = getProjectAclSqlCondition();
        final String projectAclCondition = projectAclConditionAndParams.getKey();
        final Map<String, Object> projectAclConditionParams = projectAclConditionAndParams.getValue();

        // language=SQL
        var sqlQuery = """
                SELECT "NAME" AS "name"
                     , (SELECT COUNT(*)
                          FROM "PROJECTS_TAGS"
                         INNER JOIN "PROJECT"
                            ON "PROJECT"."ID" = "PROJECTS_TAGS"."PROJECT_ID"
                         WHERE "PROJECTS_TAGS"."TAG_ID" = "TAG"."ID"
                           AND %s
                       ) AS "projectCount"
                     , (SELECT COUNT(*)
                          FROM "POLICY_TAGS"
                         WHERE "POLICY_TAGS"."TAG_ID" = "TAG"."ID"
                       ) AS "policyCount"
                     , COUNT(*) OVER() AS "totalCount"
                  FROM "TAG"
                """.formatted(projectAclCondition);

        final var params = new HashMap<>(projectAclConditionParams);

        if (filter != null) {
            sqlQuery += " WHERE \"NAME\" LIKE :nameFilter";
            params.put("nameFilter", "%" + filter.toLowerCase() + "%");
        }

        if (orderBy == null) {
            sqlQuery += " ORDER BY \"name\" ASC";
        } else if ("name".equals(orderBy) || "projectCount".equals(orderBy) || "policyCount".equals(orderBy)) {
            sqlQuery += " ORDER BY \"%s\" %s, \"ID\" ASC".formatted(orderBy,
                    orderDirection == OrderDirection.DESCENDING ? "DESC" : "ASC");
        } else {
            // TODO: Throw NotSortableException once Alpine opens up its constructor.
            throw new IllegalArgumentException("Cannot sort by " + orderBy);
        }

        sqlQuery += " " + getOffsetLimitSqlClause();

        final Query<?> query = pm.newQuery(Query.SQL, sqlQuery);
        query.setNamedParameters(params);
        try {
            return new ArrayList<>(query.executeResultList(TagListRow.class));
        } finally {
            query.closeAll();
        }
    }

    /**
     * @since 4.12.0
     */
    public record TaggedProjectRow(String uuid, String name, String version, long totalCount) {

        @SuppressWarnings("unused") // DataNucleus will use this for MSSQL.
        public TaggedProjectRow(String uuid, String name, String version, int totalCount) {
            this(uuid, name, version, (long) totalCount);
        }

    }

    /**
     * @since 4.12.0
     */
    @Override
    public List<TaggedProjectRow> getTaggedProjects(final String tagName) {
        final Map.Entry<String, Map<String, Object>> projectAclConditionAndParams = getProjectAclSqlCondition();
        final String projectAclCondition = projectAclConditionAndParams.getKey();
        final Map<String, Object> projectAclConditionParams = projectAclConditionAndParams.getValue();

        // language=SQL
        var sqlQuery = """
            SELECT "PROJECT"."UUID" AS "uuid"
                 , "PROJECT"."NAME" AS "name"
                 , "PROJECT"."VERSION" AS "version"
                 , COUNT(*) OVER() AS "totalCount"
              FROM "PROJECT"
             INNER JOIN "PROJECTS_TAGS"
                ON "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID"
             INNER JOIN "TAG"
                ON "TAG"."ID" = "PROJECTS_TAGS"."TAG_ID"
             WHERE "TAG"."NAME" = :tag
               AND %s
            """.formatted(projectAclCondition);

        final var params = new HashMap<>(projectAclConditionParams);
        params.put("tag", tagName);

        if (filter != null) {
            sqlQuery += " AND \"PROJECT\".\"NAME\" LIKE :nameFilter";
            params.put("nameFilter", "%" + filter + "%");
        }

        if (orderBy == null) {
            sqlQuery += " ORDER BY \"name\" ASC, \"version\" DESC";
        } else if ("name".equals(orderBy) || "version".equals(orderBy)) {
            sqlQuery += " ORDER BY \"%s\" %s, \"ID\" ASC".formatted(orderBy,
                    orderDirection == OrderDirection.DESCENDING ? "DESC" : "ASC");
        } else {
            // TODO: Throw NotSortableException once Alpine opens up its constructor.
            throw new IllegalArgumentException("Cannot sort by " + orderBy);
        }

        sqlQuery += " " + getOffsetLimitSqlClause();

        final Query<?> query = pm.newQuery(Query.SQL, sqlQuery);
        query.setNamedParameters(params);
        try {
            return new ArrayList<>(query.executeResultList(TaggedProjectRow.class));
        } finally {
            query.closeAll();
        }
    }

    /**
     * @since 4.12.0
     */
    @Override
    public void tagProjects(final String tagName, final Collection<String> projectUuids) {
        runInTransaction(() -> {
            final Tag tag = getTagByName(tagName);
            if (tag == null) {
                throw new NoSuchElementException("A tag with name %s does not exist".formatted(tagName));
            }

            final Query<Project> projectsQuery = pm.newQuery(Project.class);
            final var params = new HashMap<String, Object>(Map.of("uuids", projectUuids));
            preprocessACLs(projectsQuery, ":uuids.contains(uuid)", params, /* bypass */ false);
            projectsQuery.setNamedParameters(params);
            final List<Project> projects = executeAndCloseList(projectsQuery);

            for (final Project project : projects) {
                if (project.getTags() == null || project.getTags().isEmpty()) {
                    project.setTags(List.of(tag));
                    continue;
                }

                if (!project.getTags().contains(tag)) {
                    project.getTags().add(tag);
                }
            }
        });
    }

    /**
     * @since 4.12.0
     */
    @Override
    public void untagProjects(final String tagName, final Collection<String> projectUuids) {
        runInTransaction(() -> {
            final Tag tag = getTagByName(tagName);
            if (tag == null) {
                throw new NoSuchElementException("A tag with name %s does not exist".formatted(tagName));
            }

            final Query<Project> projectsQuery = pm.newQuery(Project.class);
            final var params = new HashMap<String, Object>(Map.of("uuids", projectUuids));
            preprocessACLs(projectsQuery, ":uuids.contains(uuid)", params, /* bypass */ false);
            projectsQuery.setNamedParameters(params);
            final List<Project> projects = executeAndCloseList(projectsQuery);

            for (final Project project : projects) {
                if (project.getTags() == null || project.getTags().isEmpty()) {
                    continue;
                }

                project.getTags().remove(tag);
            }
        });
    }

    /**
     * @since 4.12.0
     */
    public record TaggedPolicyRow(String uuid, String name, long totalCount) {

        @SuppressWarnings("unused") // DataNucleus will use this for MSSQL.
        public TaggedPolicyRow(String uuid, String name, int totalCount) {
            this(uuid, name, (long) totalCount);
        }

    }

    /**
     * @since 4.12.0
     */
    @Override
    public List<TaggedPolicyRow> getTaggedPolicies(final String tagName) {
        // language=SQL
        var sqlQuery = """
                SELECT "POLICY"."UUID" AS "uuid"
                     , "POLICY"."NAME" AS "name"
                     , COUNT(*) OVER() AS "totalCount"
                  FROM "POLICY"
                 INNER JOIN "POLICY_TAGS"
                    ON "POLICY_TAGS"."POLICY_ID" = "POLICY"."ID"
                 INNER JOIN "TAG"
                    ON "TAG"."ID" = "POLICY_TAGS"."TAG_ID"
                 WHERE "TAG"."NAME" = :tag
                """;

        final var params = new HashMap<String, Object>();
        params.put("tag", tagName);

        if (filter != null) {
            sqlQuery += " AND \"POLICY\".\"NAME\" LIKE :nameFilter";
            params.put("nameFilter", "%" + filter + "%");
        }

        if (orderBy == null) {
            sqlQuery += " ORDER BY \"name\" ASC";
        } else if ("name".equals(orderBy)) {
            sqlQuery += " ORDER BY \"%s\" %s".formatted(orderBy,
                    orderDirection == OrderDirection.DESCENDING ? "DESC" : "ASC");
        } else {
            // TODO: Throw NotSortableException once Alpine opens up its constructor.
            throw new IllegalArgumentException("Cannot sort by " + orderBy);
        }

        sqlQuery += " " + getOffsetLimitSqlClause();

        final Query<?> query = pm.newQuery(Query.SQL, sqlQuery);
        query.setNamedParameters(params);
        try {
            return new ArrayList<>(query.executeResultList(TaggedPolicyRow.class));
        } finally {
            query.closeAll();
        }
    }

    @Override
    public PaginatedResult getTagsForPolicy(String policyUuid) {

        LOGGER.debug("Retrieving tags under policy " + policyUuid);

        Policy policy = getObjectByUuid(Policy.class, policyUuid);
        List<Project> projects = policy.getProjects();

        final Stream<Tag> tags;
        if (projects != null && !projects.isEmpty()) {
            tags = projects.stream()
                    .map(Project::getTags)
                    .flatMap(List::stream)
                    .distinct();
        } else {
            tags = pm.newQuery(Tag.class).executeList().stream();
        }

        List<Tag> tagsToShow = tags.sorted(TAG_COMPARATOR).toList();

        return (new PaginatedResult()).objects(tagsToShow).total(tagsToShow.size());
    }

    /**
     * Returns a list of Tag objects what have been resolved. It resolved
     * tags by querying the database to retrieve the tag. If the tag does
     * not exist, the tag will be created and returned with other resolved
     * tags.
     *
     * @param tags a List of Tags to resolve
     * @return List of resolved Tags
     */
    public synchronized List<Tag> resolveTags(final List<Tag> tags) {
        if (tags == null) {
            return new ArrayList<>();
        }
         List<String> tagNames = tags.stream().map(tag -> tag.getName()).toList();
         return resolveTagsByName(tagNames);
    }

    public synchronized List<Tag> resolveTagsByName(final List<String> tags) {
        if (tags == null) {
            return new ArrayList<>();
        }
        final List<Tag> resolvedTags = new ArrayList<>();
        final List<String> unresolvedTags = new ArrayList<>();
        for (final String tag : tags) {
            final String trimmedTag = StringUtils.trimToNull(tag);
            if (trimmedTag != null) {
                final Tag resolvedTag = getTagByName(trimmedTag);
                if (resolvedTag != null) {
                    resolvedTags.add(resolvedTag);
                } else {
                    unresolvedTags.add(trimmedTag);
                }
            }
        }
        resolvedTags.addAll(createTags(unresolvedTags));
        return resolvedTags;
    }

    /**
     * Returns a list of Tag objects by name.
     *
     * @param name the name of the Tag
     * @return a Tag object
     */
    @Override
    public Tag getTagByName(final String name) {
        final String loweredTrimmedTag = StringUtils.lowerCase(StringUtils.trimToNull(name));
        final Query<Tag> query = pm.newQuery(Tag.class, "name == :name");
        query.setRange(0, 1);
        return singleResult(query.execute(loweredTrimmedTag));
    }

    /**
     * Creates a new Tag object with the specified name.
     *
     * @param name the name of the Tag to create
     * @return the created Tag object
     */
    @Override
    public Tag createTag(final String name) {
        final String loweredTrimmedTag = StringUtils.lowerCase(StringUtils.trimToNull(name));
        final Tag resolvedTag = getTagByName(loweredTrimmedTag);
        if (resolvedTag != null) {
            return resolvedTag;
        }
        final Tag tag = new Tag();
        tag.setName(loweredTrimmedTag);
        return persist(tag);
    }

    /**
     * Creates one or more Tag objects from the specified name(s).
     *
     * @param names the name(s) of the Tag(s) to create
     * @return the created Tag object(s)
     */
    private List<Tag> createTags(final List<String> names) {
        final List<Tag> newTags = new ArrayList<>();
        for (final String name : names) {
            final String loweredTrimmedTag = StringUtils.lowerCase(StringUtils.trimToNull(name));
            if (getTagByName(loweredTrimmedTag) == null) {
                final Tag tag = new Tag();
                tag.setName(loweredTrimmedTag);
                newTags.add(tag);
            }
        }
        return new ArrayList<>(persist(newTags));
    }
}
