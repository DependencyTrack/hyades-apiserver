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
package org.dependencytrack.filters;

import alpine.Config;
import alpine.common.metrics.Metrics;
import io.micrometer.core.instrument.Timer;

import javax.annotation.Priority;
import javax.ws.rs.Path;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * @since 5.5.0
 */
@Provider
@Priority(Priorities.USER)
public class RequestTimerFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private static final String REQUEST_START_NANOS_PROPERTY = "requestStartNanos";

    private static final Map<String, String> REQUEST_PATHS_BY_RESOURCE = new ConcurrentHashMap<>();

    @Context
    ResourceInfo resourceInfo;

    @Override
    public void filter(final ContainerRequestContext requestContext) throws IOException {
        if (!Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            return;
        }
        if ("OPTIONS".equals(requestContext.getMethod())) {
            return;
        }

        requestContext.setProperty(REQUEST_START_NANOS_PROPERTY, System.nanoTime());
    }

    @Override
    public void filter(final ContainerRequestContext requestContext, final ContainerResponseContext responseContext) throws IOException {
        if (!Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            return;
        }

        if (requestContext.getProperty(REQUEST_START_NANOS_PROPERTY) instanceof final Long requestStartNanos) {
            Timer.builder("http.server.requests")
                    .tag("path", getRequestPath())
                    .tag("method", requestContext.getMethod())
                    .tag("status", String.valueOf(responseContext.getStatus()))
                    .register(Metrics.getRegistry())
                    .record(requestStartNanos, TimeUnit.NANOSECONDS);
        }
    }

    private String getRequestPath() {
        return REQUEST_PATHS_BY_RESOURCE.computeIfAbsent(
                "%s#%s".formatted(resourceInfo.getResourceClass().getName(), resourceInfo.getResourceMethod().getName()),
                ignored -> {
                    // Resolve the request path from JAX-RS @Path annotations.
                    // For resources with path parameters, e.g. `/v1/project/{uuid}`,
                    // we don't want to have separate timers for each UUID - that'd be too much data.
                    // Hence, we can't use `requestContext.getUriInfo().getPath()`.

                    final Path classPathAnnotation = resourceInfo.getResourceClass().getDeclaredAnnotation(Path.class);
                    final Path methodPathAnnotation = resourceInfo.getResourceMethod().getDeclaredAnnotation(Path.class);

                    String requestPath = classPathAnnotation != null ? classPathAnnotation.value() : "";
                    if (methodPathAnnotation != null) {
                        final String methodPath = methodPathAnnotation.value();

                        if (!requestPath.isEmpty() && !requestPath.endsWith("/") && !methodPath.startsWith("/")) {
                            requestPath += "/";
                        }

                        requestPath += methodPathAnnotation.value();
                    }

                    return requestPath;
                });
    }

}
