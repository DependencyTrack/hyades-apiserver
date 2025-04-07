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

import alpine.common.validation.RegexSequence;
import alpine.common.validation.ValidationTask;
import alpine.model.ApiKey;
import alpine.model.Team;
import alpine.model.UserPrincipal;
import alpine.server.auth.PermissionRequired;
import com.google.protobuf.Any;
import com.google.protobuf.util.Timestamps;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.AnalysisDao;
import org.dependencytrack.persistence.jdbi.ComponentDao;
import org.dependencytrack.persistence.jdbi.NotificationSubjectDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.persistence.jdbi.VulnerabilityDao;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.AnalysisRequest;
import org.dependencytrack.util.AnalysisCommentFormatter.AnalysisCommentField;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_PROJECT_AUDIT_CHANGE;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.util.AnalysisCommentFormatter.formatComment;
import static org.dependencytrack.util.NotificationUtil.generateNotificationTitle;
import static org.dependencytrack.util.NotificationUtil.generateTitle;

/**
 * JAX-RS resources for processing analysis decisions.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@Path("/v1/analysis")
@Tag(name = "analysis")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class AnalysisResource extends AbstractApiResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Retrieves an analysis trail",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "An analysis trail",
                    content = @Content(schema = @Schema(implementation = Analysis.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project, component, or vulnerability could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response retrieveAnalysis(@Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"))
                                     @QueryParam("project") @ValidUuid String projectUuid,
                                     @Parameter(description = "The UUID of the component", schema = @Schema(type = "string", format = "uuid"), required = true)
                                     @QueryParam("component") @ValidUuid String componentUuid,
                                     @Parameter(description = "The UUID of the vulnerability", schema = @Schema(type = "string", format = "uuid"), required = true)
                                     @QueryParam("vulnerability") @ValidUuid String vulnerabilityUuid) {
        failOnValidationError(
                new ValidationTask(RegexSequence.Pattern.UUID, projectUuid, "Project is not a valid UUID", false), // this is optional
                new ValidationTask(RegexSequence.Pattern.UUID, componentUuid, "Component is not a valid UUID"),
                new ValidationTask(RegexSequence.Pattern.UUID, vulnerabilityUuid, "Vulnerability is not a valid UUID")
        );
        try (QueryManager qm = new QueryManager()) {
            if (StringUtils.trimToNull(projectUuid) != null) {
                final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                if (project == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
                }
            }
            final Component component = qm.getObjectByUuid(Component.class, componentUuid);
            if (component == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
            requireAccess(qm, component.getProject());
            final Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, vulnerabilityUuid);
            if (vulnerability == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The vulnerability could not be found.").build();
            }
            final Analysis analysis = qm.getAnalysis(component, vulnerability);
            if (analysis == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("No analysis exists.").build();
            }
            return Response.ok(analysis).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Records an analysis decision",
            description = "<p>Requires permission <strong>VULNERABILITY_ANALYSIS</strong></strong> or <strong>VULNERABILITY_ANALYSIS_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The created analysis",
                    content = @Content(schema = @Schema(implementation = Analysis.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project, component, or vulnerability could not be found")
    })
    @PermissionRequired({Permissions.Constants.VULNERABILITY_ANALYSIS, Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE})
    public Response updateAnalysis(AnalysisRequest request) {
        final Validator validator = getValidator();
        failOnValidationError(
                validator.validateProperty(request, "project"),
                validator.validateProperty(request, "component"),
                validator.validateProperty(request, "vulnerability"),
                validator.validateProperty(request, "analysisState"),
                validator.validateProperty(request, "analysisJustification"),
                validator.validateProperty(request, "analysisResponse"),
                validator.validateProperty(request, "analysisDetails"),
                validator.validateProperty(request, "comment")
        );
        return inJdbiTransaction(getAlpineRequest(), handle -> {
            var projectId = handle.attach(ProjectDao.class).getProjectId(UUID.fromString(request.getProject()));
            if (projectId == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            var componentUuid = UUID.fromString(request.getComponent());
            var componentId = handle.attach(ComponentDao.class).getComponentId(componentUuid);
            if (componentId == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
            requireComponentAccess(handle, componentUuid);
            var vulnUuid = UUID.fromString(request.getVulnerability());
            var vulnerabilityId = handle.attach(VulnerabilityDao.class).getVulnerabilityId(vulnUuid);
            if (vulnerabilityId == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The vulnerability could not be found.").build();
            }

            final String commenter;
            if (getPrincipal() instanceof UserPrincipal principal) {
                commenter = principal.getUsername();
            } else if (getPrincipal() instanceof ApiKey apiKey) {
                List<Team> teams = apiKey.getTeams();
                List<String> teamNames = new ArrayList<>();
                teams.forEach(team -> teamNames.add(team.getName()));
                commenter = String.join(", ", teamNames);
            } else {
                commenter = null;
            }

            boolean analysisStateChange;
            boolean suppressionChange = false;

            final var dao = handle.attach(AnalysisDao.class);
            var analysis = dao.getAnalysis(componentId, vulnerabilityId);
            if (analysis != null) {
                // Existing Analysis
                analysisStateChange = dao.makeStateComment(analysis, request.getAnalysisState(), commenter);
                dao.makeJustificationComment(analysis, request.getAnalysisJustification(), commenter);
                dao.makeAnalysisResponseComment(analysis, request.getAnalysisResponse(), commenter);
                dao.makeAnalysisDetailsComment(analysis, request.getAnalysisDetails(), commenter);
                suppressionChange = dao.makeAnalysisSuppressionComment(analysis, request.isSuppressed(), commenter);
                analysis = dao.makeAnalysis(projectId, componentId, vulnerabilityId, request.getAnalysisState(),
                        request.getAnalysisJustification(), request.getAnalysisResponse(), request.getAnalysisDetails(),
                        suppressionChange ? request.isSuppressed() : analysis.isSuppressed());
            } else {
                // New Analysis
                analysis = dao.makeAnalysis(projectId, componentId, vulnerabilityId, request.getAnalysisState(),
                        request.getAnalysisJustification(), request.getAnalysisResponse(), request.getAnalysisDetails(),
                        request.isSuppressed() == null ? false : request.isSuppressed());
                analysisStateChange = true; // this is a new analysis - so set to true because it was previously null
                if (AnalysisState.NOT_SET != request.getAnalysisState()) {
                    dao.makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentField.STATE, AnalysisState.NOT_SET, request.getAnalysisState()), commenter);
                }
            }
            dao.makeAnalysisComment(analysis.getId(), StringUtils.trimToNull(request.getComment()), commenter);
            if (analysisStateChange || suppressionChange) {
                var notificationTitle = generateTitle(analysis.getAnalysisState(), analysis.isSuppressed(), analysisStateChange, suppressionChange);
                handle.attach(NotificationSubjectDao.class).getForProjectAuditChange(componentUuid, vulnUuid, analysis.getAnalysisState(), analysis.isSuppressed())
                        .map(subject -> org.dependencytrack.proto.notification.v1.Notification.newBuilder()
                                .setScope(SCOPE_PORTFOLIO)
                                .setGroup(GROUP_PROJECT_AUDIT_CHANGE)
                                .setLevel(LEVEL_INFORMATIONAL)
                                .setTimestamp(Timestamps.now())
                                .setTitle(generateNotificationTitle(notificationTitle, subject.getProject()))
                                .setContent("An analysis decision was made to a finding affecting a project")
                                .setSubject(Any.pack(subject))
                                .build())
                        .ifPresent(notification -> new KafkaEventDispatcher().dispatchNotificationProto(notification));
            }
            analysis.setAnalysisComments(dao.getComments(analysis.getId()));
            return Response.ok(analysis).build();
        });
    }
}
