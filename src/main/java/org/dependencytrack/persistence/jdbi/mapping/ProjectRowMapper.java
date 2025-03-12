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
package org.dependencytrack.persistence.jdbi.mapping;

import org.cyclonedx.model.ExternalReference;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.converter.OrganizationalContactsJsonConverter;
import org.dependencytrack.persistence.converter.OrganizationalEntityJsonConverter;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import com.fasterxml.jackson.core.type.TypeReference;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.deserializeJson;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class ProjectRowMapper implements RowMapper<Project> {

    private static final TypeReference<List<ExternalReference>> EXTERNAL_REFS_TYPE_REF = new TypeReference<>() {
    };

    @Override
    public Project map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final var project = new Project();

        maybeSet(rs, "ID", ResultSet::getLong, project::setId);
        maybeSet(rs, "CLASSIFIER", ResultSet::getString, Classifier::valueOf);
        maybeSet(rs, "CPE", ResultSet::getString, project::setCpe);
        maybeSet(rs, "DESCRIPTION", ResultSet::getString, project::setDescription);
        maybeSet(rs, "DIRECT_DEPENDENCIES", ResultSet::getString, project::setDirectDependencies);
        deserializeJson(rs, "EXTERNAL_REFERENCES", EXTERNAL_REFS_TYPE_REF);
        maybeSet(rs, "GROUP", ResultSet::getString, project::setGroup);
        maybeSet(rs, "LAST_BOM_IMPORTED", ResultSet::getDate, project::setLastBomImport);
        maybeSet(rs, "LAST_BOM_IMPORTED_FORMAT", ResultSet::getString, project::setLastBomImportFormat);
        maybeSet(rs, "LAST_RISKSCORE", ResultSet::getDouble, project::setLastInheritedRiskScore);
        maybeSet(rs, "NAME", ResultSet::getString, project::setName);
        maybeSet(rs, "PARENT_PROJECT_ID", ResultSet::getLong, value -> {
            var parent = new Project();
            parent.setId(value);
            project.setParent(parent);
        });
        maybeSet(rs, "PUBLISHER", ResultSet::getString, project::setPublisher);
        maybeSet(rs, "PURL", ResultSet::getString, project::setPurl);
        maybeSet(rs, "SWIDTAGID", ResultSet::getString, project::setSwidTagId);
        maybeSet(rs, "UUID", ResultSet::getString, value -> {
            var uuid = UUID.fromString(value);
            project.setUuid(uuid);
        });
        maybeSet(rs, "VERSION", ResultSet::getString, project::setVersion);
        maybeSet(rs, "SUPPLIER", ResultSet::getString, value -> {
            var converter = new OrganizationalEntityJsonConverter();
            project.setSupplier(converter.convertToAttribute(value));
        });
        maybeSet(rs, "MANUFACTURER", ResultSet::getString, value -> {
            var converter = new OrganizationalEntityJsonConverter();
            project.setManufacturer(converter.convertToAttribute(value));
        });
        maybeSet(rs, "AUTHORS", ResultSet::getString, values -> {
            var converter = new OrganizationalContactsJsonConverter();
            project.setAuthors(converter.convertToAttribute(values));
        });

        return project;
    }

}