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
package org.dependencytrack.workflow;

import org.cyclonedx.proto.v1_6.Bom;
import org.dependencytrack.analysis.vulnerability.VulnAnalyzer;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsResult;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.workflow.framework.ActivityClient;
import org.dependencytrack.workflow.framework.ActivityContext;
import org.dependencytrack.workflow.framework.ActivityExecutor;
import org.dependencytrack.workflow.framework.annotation.Activity;
import org.dependencytrack.workflow.framework.failure.ApplicationFailureException;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.UUID;

import static org.dependencytrack.workflow.framework.payload.PayloadConverters.protoConverter;

@Activity(name = "analyze-project-vulns")
public class AnalyzeProjectVulnsActivity implements ActivityExecutor<AnalyzeProjectVulnsArgs, AnalyzeProjectVulnsResult> {

    private final Map<String, VulnAnalyzer> analyzerByName = new HashMap<>();

    public static final ActivityClient<AnalyzeProjectVulnsArgs, AnalyzeProjectVulnsResult> CLIENT = ActivityClient.of(
            AnalyzeProjectVulnsActivity.class,
            protoConverter(AnalyzeProjectVulnsArgs.class),
            protoConverter(AnalyzeProjectVulnsResult.class));

    public AnalyzeProjectVulnsActivity() {
        this(ServiceLoader.load(VulnAnalyzer.class).stream()
                .map(ServiceLoader.Provider::get).toList());
    }

    AnalyzeProjectVulnsActivity(final Collection<VulnAnalyzer> analyzers) {
        for (final VulnAnalyzer analyzer : analyzers) {
            analyzerByName.put(analyzer.name(), analyzer);
        }
    }

    @Override
    public Optional<AnalyzeProjectVulnsResult> execute(final ActivityContext<AnalyzeProjectVulnsArgs> ctx) throws Exception {
        final AnalyzeProjectVulnsArgs args = ctx.argument().orElseThrow();

        final VulnAnalyzer analyzer = analyzerByName.get(args.getAnalyzerName());
        if (analyzer == null) {
            throw new ApplicationFailureException(
                    "No vulnerability analyzer found for name " + args.getAnalyzerName(),
                    /* cause */ null,
                    /* isTerminal */ true);
        }

        final Bom vdr = analyzer.analyzeProject(UUID.fromString(args.getProject().getUuid()));

        final FileMetadata vdrFileMetadata;
        try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
            vdrFileMetadata = fileStorage.store("vdr.proto", vdr.toByteArray());
        }

        return Optional.of(AnalyzeProjectVulnsResult.newBuilder()
                .setAnalyzer(args.getAnalyzerName())
                .setVdrFileMetadata(vdrFileMetadata)
                .build());
    }

}
