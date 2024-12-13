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

import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsResult;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsResultX;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessProjectAnalysisResultsArgs;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.workflow.annotation.Activity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Optional;

@Activity(name = "process-project-analysis-results")
public class ProcessProjectAnalysisResultsActivity implements ActivityRunner<ProcessProjectAnalysisResultsArgs, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProcessProjectAnalysisResultsActivity.class);

    @Override
    public Optional<Void> run(final ActivityRunContext<ProcessProjectAnalysisResultsArgs> ctx) throws Exception {
        final ProcessProjectAnalysisResultsArgs args = ctx.argument().orElseThrow();

        final var resultsFileKeys = new HashSet<String>(args.getResultsCount());
        final var results = new ArrayList<AnalyzeProjectVulnsResult>(args.getResultsCount());

        try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
            for (final AnalyzeProjectVulnsResultX result : args.getResultsList()) {
                if (!result.hasResultsFileMetadata()) {
                    continue;
                }

                final String fileKey = result.getResultsFileMetadata().getKey();
                resultsFileKeys.add(fileKey);

                LOGGER.info("Retrieving results file {}", fileKey);
                final byte[] fileContent = fileStorage.get(fileKey);
                results.add(AnalyzeProjectVulnsResult.parseFrom(fileContent));
            }
        }

        LOGGER.info("Processing {} results", results.size());

        try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
            for (final String fileKey : resultsFileKeys) {
                LOGGER.info("Deleting results file {}", fileKey);
                fileStorage.delete(fileKey);
            }
        }

        return Optional.empty();
    }

}
