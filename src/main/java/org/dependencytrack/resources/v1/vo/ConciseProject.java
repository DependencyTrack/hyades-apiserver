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
package org.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Tag;
import org.dependencytrack.persistence.jdbi.ProjectDao.ConciseProjectListRow;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * @since 5.5.0
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@ApiModel(description = "A concise representation of a project")
public record ConciseProject(
        @ApiModelProperty(value = "UUID of the project", required = true) UUID uuid,
        @ApiModelProperty(value = "Group or namespace of the project") String group,
        @ApiModelProperty(value = "Name of the project", required = true) String name,
        @ApiModelProperty(value = "Version of the project") String version,
        @ApiModelProperty(value = "Classifier of the project") Classifier classifier,
        @ApiModelProperty(value = "Whether the project is active", required = true) boolean active,
        @ApiModelProperty(value = "Tags associated with the project") List<Tag> tags,
        @ApiModelProperty(value = "Timestamp of the last BOM import", dataType = "number", example = "1719499619599") Date lastBomImport,
        @ApiModelProperty(value = "Format of the last imported BOM") String lastBomImportFormat,
        @ApiModelProperty(value = "Whether the project has children", required = true) boolean hasChildren,
        @ApiModelProperty(value = "Latest metrics for the project") ConciseProjectMetrics metrics
) {

    public ConciseProject(final ConciseProjectListRow row) {
        this(row.uuid(), row.group(), row.name(), row.version(),
                row.classifier() != null ? Classifier.valueOf(row.classifier()) : null,
                row.active(),
                convertTags(row.tags()),
                row.lastBomImport() != null ? Date.from(row.lastBomImport()) : null,
                row.lastBomImportFormat(),
                row.hasChildren(),
                row.metrics() != null ? new ConciseProjectMetrics(row.metrics()) : null);
    }

    private static List<Tag> convertTags(final Collection<String> tagNames) {
        if (tagNames == null || tagNames.isEmpty()) {
            return Collections.emptyList();
        }

        return tagNames.stream()
                .map(tagName -> {
                    final var tag = new Tag();
                    tag.setName(tagName);
                    return tag;
                })
                .toList();
    }

}
