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
package org.dependencytrack.resources.v2.exception;

import org.dependencytrack.api.v2.model.ProblemDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ResourceContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * {@link ExceptionMapper} for generic {@link ServerErrorException}s.
 * <p>
 * This mapper is roughly the same as {@link DefaultExceptionMapper},
 * except that it communicates the status code provided by the {@link ServerErrorException}
 * to client, instead of a generic {@link Response.Status#INTERNAL_SERVER_ERROR}.
 *
 * @since 5.6.0
 */
@Provider
public class ServerErrorExceptionMapper extends ProblemDetailsExceptionMapper<ServerErrorException, ProblemDetails> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ServerErrorExceptionMapper.class);

    @Context
    private ResourceContext resourceContext;

    @Override
    public ProblemDetails map(final ServerErrorException exception) {
        LOGGER.error("Unexpected server error occurred during request processing", exception);

        var errorDetails = "An error occurred that was not anticipated.";

        // NB: The request ID is also sent via x-request-id response header.
        // Providing it in the error details is for humans only.
        final var requestContext = resourceContext.getResource(ContainerRequestContext.class);
        if (requestContext.getProperty("requestId") instanceof final String requestId) {
            errorDetails += " Contact your administrators and provide them the following request ID: " + requestId;
        }

        return ProblemDetails.builder()
                .status(exception.getResponse().getStatus())
                .title(exception.getResponse().getStatusInfo().getReasonPhrase())
                .detail(errorDetails)
                .build();
    }

}
