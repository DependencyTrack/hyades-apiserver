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
package org.dependencytrack.resources.v1;

import alpine.persistence.PaginatedResult;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ResponseHeader;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.TagDao;
import org.dependencytrack.persistence.jdbi.TagDao.TagListRow;
import org.dependencytrack.persistence.jdbi.TagDao.TaggedProjectRow;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

@Path("/v1/tag")
@Api(value = "tag", authorizations = @Authorization(value = "X-Api-Key"))
public class TagResource extends AlpineResource {

    public record TagListResponseItem(String name, int projectCount, int policyCount) {
    }

    public record TaggedProjectListResponseItem(UUID uuid, String name, String version) {
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @PaginatedApi
    @ApiOperation(
            value = "Returns a list of all tags",
            response = TagListResponseItem.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of tags"),
            notes = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getAllTags() {
        final List<TagListRow> tagListRows = withJdbiHandle(getAlpineRequest(),
                handle -> handle.attach(TagDao.class).getTags());

        final List<TagListResponseItem> tags = tagListRows.stream()
                .map(tagRow -> new TagListResponseItem(tagRow.name(), tagRow.projectCount(), tagRow.policyCount()))
                .toList();
        final int totalCount = tagListRows.isEmpty() ? 0 : tagListRows.getFirst().totalCount();
        return Response.ok(tags).header(TOTAL_COUNT_HEADER, totalCount).build();
    }

    @GET
    @Path("/{name}/project")
    @Produces(MediaType.APPLICATION_JSON)
    @PaginatedApi
    @ApiOperation(
            value = "Returns a list of projects tagged with a given tag",
            response = TaggedProjectListResponseItem.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of tags"),
            notes = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getTaggedProjects(@PathParam("name") final String tagName) {
        final List<TaggedProjectRow> tagListRows = withJdbiHandle(getAlpineRequest(),
                handle -> handle.attach(TagDao.class).getTaggedProjects(tagName));

        final List<TaggedProjectListResponseItem> tags = tagListRows.stream()
                .map(row -> new TaggedProjectListResponseItem(row.uuid(), row.name(), row.version()))
                .toList();
        final int totalCount = tagListRows.isEmpty() ? 0 : tagListRows.getFirst().totalCount();
        return Response.ok(tags).header(TOTAL_COUNT_HEADER, totalCount).build();
    }

    @GET
    @Path("/{policyUuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all tags associated with a given policy",
            response = Tag.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of tags"),
            notes = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getTags(@ApiParam(value = "The UUID of the policy", format = "uuid", required = true)
                            @PathParam("policyUuid") @ValidUuid String policyUuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getTags(policyUuid);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }
}
