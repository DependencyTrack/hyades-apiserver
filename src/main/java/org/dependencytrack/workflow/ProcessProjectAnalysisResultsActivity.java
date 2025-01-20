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
import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsResult;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsResultX;
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessProjectAnalysisResultsArgs;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.workflow.framework.ActivityClient;
import org.dependencytrack.workflow.framework.ActivityRunContext;
import org.dependencytrack.workflow.framework.ActivityRunner;
import org.dependencytrack.workflow.framework.annotation.Activity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Optional;

import static org.dependencytrack.workflow.framework.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.voidConverter;

@Activity(name = "process-project-analysis-results")
public class ProcessProjectAnalysisResultsActivity implements ActivityRunner<ProcessProjectAnalysisResultsArgs, Void> {

    public static final ActivityClient<ProcessProjectAnalysisResultsArgs, Void> CLIENT = ActivityClient.of(
            ProcessProjectAnalysisResultsActivity.class,
            protoConverter(ProcessProjectAnalysisResultsArgs.class),
            voidConverter());

    private static final Logger LOGGER = LoggerFactory.getLogger(ProcessProjectAnalysisResultsActivity.class);

    @Override
    public Optional<Void> run(final ActivityRunContext<ProcessProjectAnalysisResultsArgs> ctx) throws Exception {
        final ProcessProjectAnalysisResultsArgs args = ctx.argument().orElseThrow();

        final var resultsFileMetadataSet = new HashSet<FileMetadata>(args.getResultsCount());
        final var results = new ArrayList<AnalyzeProjectVulnsResult>(args.getResultsCount());

        try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
            for (final AnalyzeProjectVulnsResultX result : args.getResultsList()) {
                if (!result.hasResultsFileMetadata()) {
                    continue;
                }

                resultsFileMetadataSet.add(result.getResultsFileMetadata());

                // TODO: Fail with a terminal exception when a file was not found?
                //  Consider checking for all files first so we can report when more
                //  than one file is missing.
                LOGGER.info("Retrieving results file {}", result.getResultsFileMetadata().getKey());
                final byte[] fileContent = fileStorage.get(result.getResultsFileMetadata());
                results.add(AnalyzeProjectVulnsResult.parseFrom(fileContent));
            }
        }

        LOGGER.info("Processing {} results", results.size());

        // TODO:
        //   1. Collect unique vulnerabilities across all results.
        //     a. If multiple analyzers report the same vulnerability,
        //        use a deterministic algorithm to pick the data we want to use.
        //   2. Synchronize vulnerabilities with database if needed (single trx, batching).
        //     a. Internal analyzer only reports vulnId & source, not sync needed for that.
        //     b. Be mindful of unique constraint errors upon trx commit. Is very likely
        //        when new vulns are reported multiple times in parallel.
        //   3. Load applicable vulnerability policies.
        //   4. Map synchronized vulnerabilities to component IDs.
        //     a. Keep track of which analyzer reported what. That allows us to automatically
        //        suppress findings that no analyzer reports anymore.
        //   5. Synchronize component<->vulnerability relationships with database (single trx, batching).
        //   6. Evaluate vulnerability policies.
        //   7. Apply policy results if needed (single trx, batching).
        //  Most of this already exists in VulnerabilityScanResultProcessor.
        //  The difference is that the processor does all this for a single component at a time,
        //  whereas here we'll deal with all components of a project.

        try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
            for (final FileMetadata fileMetadata : resultsFileMetadataSet) {
                LOGGER.info("Deleting results file {}", fileMetadata.getKey());
                fileStorage.delete(fileMetadata);
            }
        }

        return Optional.empty();
    }

}
