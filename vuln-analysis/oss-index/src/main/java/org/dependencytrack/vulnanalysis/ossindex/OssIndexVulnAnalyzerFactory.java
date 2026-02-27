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
package org.dependencytrack.vulnanalysis.ossindex;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerFactory;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerRequirement;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.EnumSet;

import static com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES;
import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
final class OssIndexVulnAnalyzerFactory implements VulnAnalyzerFactory {

    private @Nullable ConfigRegistry configRegistry;
    private @Nullable CacheManager cacheManager;
    private @Nullable HttpClient httpClient;
    private @Nullable ObjectMapper objectMapper;

    @Override
    public String extensionName() {
        return "oss-index";
    }

    @Override
    public Class<? extends VulnAnalyzer> extensionClass() {
        return OssIndexVulnAnalyzer.class;
    }

    @Override
    public void init(ExtensionContext ctx) {
        configRegistry = ctx.configRegistry();
        cacheManager = ctx.cacheManager();
        httpClient = HttpClient.newBuilder()
                .proxy(ctx.proxySelector())
                .build();
        objectMapper = new ObjectMapper()
                .disable(FAIL_ON_UNKNOWN_PROPERTIES);
    }

    @Override
    public VulnAnalyzer create() {
        requireNonNull(configRegistry);
        requireNonNull(cacheManager);
        requireNonNull(httpClient);
        requireNonNull(objectMapper);

        final var config = configRegistry.getRuntimeConfig(OssIndexVulnAnalyzerConfigV1.class);
        if (!config.isEnabled()) {
            throw new IllegalStateException("Analyzer is disabled");
        }

        return new OssIndexVulnAnalyzer(
                cacheManager.getCache("results"),
                httpClient,
                objectMapper,
                config.getApiUrl(),
                config.getUsername(),
                config.getApiToken(),
                config.isAliasSyncEnabled());
    }

    @Override
    public boolean isEnabled() {
        requireNonNull(configRegistry);
        return configRegistry.getRuntimeConfig(OssIndexVulnAnalyzerConfigV1.class).isEnabled();
    }

    @Override
    public EnumSet<VulnAnalyzerRequirement> analyzerRequirements() {
        return EnumSet.of(VulnAnalyzerRequirement.COMPONENT_PURL);
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        return RuntimeConfigSpec.of(
                new OssIndexVulnAnalyzerConfigV1()
                        .withEnabled(false)
                        .withApiUrl(URI.create("https://ossindex.sonatype.org")),
                config -> {
                    if (!config.isEnabled()) {
                        return;
                    }
                    if (config.getApiUrl() == null) {
                        throw new InvalidRuntimeConfigException("No API URL provided");
                    }
                    if (config.getUsername() == null) {
                        throw new InvalidRuntimeConfigException("No username provided");
                    }
                    if (config.getApiToken() == null) {
                        throw new InvalidRuntimeConfigException("No API token provided");
                    }
                });
    }

    @Override
    public void close() {
        if (httpClient != null) {
            httpClient.close();
        }
    }

}
