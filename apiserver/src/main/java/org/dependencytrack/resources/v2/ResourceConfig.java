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
package org.dependencytrack.resources.v2;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import alpine.server.filters.AuthorizationFeature;
import alpine.server.filters.GZipInterceptor;
import alpine.server.filters.HeaderFilter;
import alpine.server.filters.RequestIdFilter;
import alpine.server.filters.RequestMdcEnrichmentFilter;
import org.dependencytrack.filters.JerseyMetricsFeature;
import org.dependencytrack.plugin.PluginManagerBinder;
import org.dependencytrack.workflow.WorkflowEngineBinder;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.glassfish.jersey.media.multipart.MultiPartFeature;

import static org.glassfish.jersey.server.ServerProperties.PROVIDER_PACKAGES;
import static org.glassfish.jersey.server.ServerProperties.PROVIDER_SCANNING_RECURSIVE;

/**
 * @since 5.6.0
 */
public final class ResourceConfig extends org.glassfish.jersey.server.ResourceConfig {

    public ResourceConfig() {
        // Only scan the v2 package for providers, register everything else manually.
        // This gives us more flexibility to pick-and-choose, and potentially configure
        // specific features that do not necessarily overlap with v1.
        property(PROVIDER_PACKAGES, getClass().getPackageName());
        property(PROVIDER_SCANNING_RECURSIVE, true);

        register(ApiFilter.class);
        register(AuthenticationFeature.class);
        register(AuthorizationFeature.class);
        register(GZipInterceptor.class);
        register(HeaderFilter.class);
        register(JacksonFeature.withoutExceptionMappers());
        register(JerseyMetricsFeature.class);
        register(MultiPartFeature.class);
        register(RequestIdFilter.class);
        register(RequestMdcEnrichmentFilter.class);

        register(PluginManagerBinder.class);
        register(WorkflowEngineBinder.class);
    }

}
