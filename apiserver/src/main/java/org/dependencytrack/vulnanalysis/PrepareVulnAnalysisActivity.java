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
package org.dependencytrack.vulnanalysis;

import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Component;
import org.cyclonedx.proto.v1_6.Property;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.plugin.NoSuchExtensionException;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.PrepareVulnAnalysisArg;
import org.dependencytrack.proto.internal.workflow.v1.PrepareVulnAnalysisRes;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerFactory;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerRequirement;
import org.jdbi.v3.core.statement.Query;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_ANALYZER_NAME;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.7.0
 */
@ActivitySpec(name = "prepare-vuln-analysis")
public final class PrepareVulnAnalysisActivity implements Activity<PrepareVulnAnalysisArg, PrepareVulnAnalysisRes> {

    private static final Logger LOGGER = LoggerFactory.getLogger(PrepareVulnAnalysisActivity.class);

    private final PluginManager pluginManager;

    public PrepareVulnAnalysisActivity(PluginManager pluginManager) {
        this.pluginManager = pluginManager;
    }

    @Override
    public PrepareVulnAnalysisRes execute(
            ActivityContext ctx,
            @Nullable PrepareVulnAnalysisArg argument) throws Exception {
        if (argument == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        try (var ignored = MDC.putCloseable(MDC_PROJECT_UUID, argument.getProjectUuid())) {
            LOGGER.debug("Determining applicable analyzers");
            final Map<String, Set<VulnAnalyzerRequirement>> requirementsByAnalyzer = getApplicableAnalyzers();
            if (requirementsByAnalyzer.isEmpty()) {
                LOGGER.debug("No applicable analyzers");
                return PrepareVulnAnalysisRes.getDefaultInstance();
            }
            LOGGER.debug("Applicable analyzers: {}", requirementsByAnalyzer);

            LOGGER.debug("Assembling BOM for analysis");
            final Bom bom = assembleBom(
                    argument.getProjectUuid(),
                    requirementsByAnalyzer.values().stream()
                            .flatMap(Collection::stream)
                            .collect(Collectors.toSet()));
            if (bom.getComponentsCount() == 0) {
                LOGGER.debug("Project has no analyzable components");
                return PrepareVulnAnalysisRes.getDefaultInstance();
            }
            LOGGER.debug("Assembled BOM of {} components", bom.getComponentsCount());

            final FileMetadata bomFileMetadata = storeBom(ctx, bom);
            LOGGER.debug("Stored BOM file at {}", bomFileMetadata.getLocation());

            return PrepareVulnAnalysisRes.newBuilder()
                    .addAllAnalyzers(requirementsByAnalyzer.keySet())
                    .setBomFileMetadata(bomFileMetadata)
                    .build();
        }
    }

    private Map<String, Set<VulnAnalyzerRequirement>> getApplicableAnalyzers() {
        final var requirementsByAnalyzer = new HashMap<String, Set<VulnAnalyzerRequirement>>();
        for (final var factory : pluginManager.getFactories(VulnAnalyzer.class)) {
            final var vulnAnalyzerFactory = (VulnAnalyzerFactory) factory;
            final var analyzerName = vulnAnalyzerFactory.extensionName();

            try (var ignored = MDC.putCloseable(MDC_VULN_ANALYZER_NAME, analyzerName)) {
                if (vulnAnalyzerFactory.isEnabled()) {
                    LOGGER.debug("Analyzer is enabled");
                    requirementsByAnalyzer
                            .computeIfAbsent(analyzerName, k -> new HashSet<>())
                            .addAll(vulnAnalyzerFactory.analyzerRequirements());
                } else {
                    LOGGER.debug("Analyzer is disabled");
                }
            }
        }

        return requirementsByAnalyzer;
    }

    private Bom assembleBom(String projectUuid, Set<VulnAnalyzerRequirement> requirements) {
        final List<Component> components = withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT "ID"
                         , "GROUP"
                         , "NAME"
                         , "VERSION"
                         , "INTERNAL"
                    <#if requirements?seq_contains('COMPONENT_CPE')>
                         , "CPE"
                    </#if>
                    <#if requirements?seq_contains('COMPONENT_PURL')>
                         , "PURL"
                    </#if>
                      FROM "COMPONENT"
                     WHERE "PROJECT_ID" = (SELECT "ID" FROM "PROJECT" WHERE "UUID" = CAST(:projectUuid AS UUID))
                    """);

            return query
                    .bind("projectUuid", projectUuid)
                    .define("requirements", requirements)
                    .map((rs, stmtCtx) -> {
                        final var componentBuilder = Component.newBuilder()
                                .setBomRef(rs.getString("ID"))
                                .setName(rs.getString("NAME"));
                        Optional.ofNullable(rs.getString("GROUP"))
                                .ifPresent(componentBuilder::setGroup);
                        Optional.ofNullable(rs.getString("VERSION"))
                                .ifPresent(componentBuilder::setVersion);
                        if (rs.getBoolean("INTERNAL")) {
                            componentBuilder.addProperties(
                                    Property.newBuilder()
                                            .setName("dependencytrack:internal:is-internal-component")
                                            .setValue("true")
                                            .build());
                        }
                        if (requirements.contains(VulnAnalyzerRequirement.COMPONENT_CPE)) {
                            Optional.ofNullable(rs.getString("CPE"))
                                    .ifPresent(componentBuilder::setCpe);
                        }
                        if (requirements.contains(VulnAnalyzerRequirement.COMPONENT_PURL)) {
                            Optional.ofNullable(rs.getString("PURL"))
                                    .ifPresent(componentBuilder::setPurl);
                        }
                        return componentBuilder.build();
                    })
                    .list();
        });

        return Bom.newBuilder()
                .addAllComponents(components)
                .build();
    }

    private FileMetadata storeBom(ActivityContext ctx, Bom bom) throws IOException {
        try (final var fileStorage = pluginManager.getExtension(FileStorage.class)) {
            return fileStorage.store(
                    "vuln-analysis/%s/bom.proto".formatted(ctx.workflowRunId()),
                    "application/protobuf",
                    new ByteArrayInputStream(bom.toByteArray()));
        } catch (NoSuchExtensionException e) {
            throw new TerminalApplicationFailureException(e);
        }
    }

}
