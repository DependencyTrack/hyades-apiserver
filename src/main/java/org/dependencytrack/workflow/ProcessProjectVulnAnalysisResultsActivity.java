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
import org.dependencytrack.proto.workflow.payload.v1alpha1.ProcessProjectVulnAnalysisResultsArgs;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.workflow.framework.ActivityClient;
import org.dependencytrack.workflow.framework.ActivityContext;
import org.dependencytrack.workflow.framework.ActivityExecutor;
import org.dependencytrack.workflow.framework.annotation.Activity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Optional;

import static org.dependencytrack.workflow.framework.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.voidConverter;

@Activity(name = "process-project-analysis-results")
public class ProcessProjectVulnAnalysisResultsActivity implements ActivityExecutor<ProcessProjectVulnAnalysisResultsArgs, Void> {

    public static final ActivityClient<ProcessProjectVulnAnalysisResultsArgs, Void> CLIENT = ActivityClient.of(
            ProcessProjectVulnAnalysisResultsActivity.class,
            protoConverter(ProcessProjectVulnAnalysisResultsArgs.class),
            voidConverter());

    private static final Logger LOGGER = LoggerFactory.getLogger(ProcessProjectVulnAnalysisResultsActivity.class);

    @Override
    public Optional<Void> execute(final ActivityContext<ProcessProjectVulnAnalysisResultsArgs> ctx) throws Exception {
        final ProcessProjectVulnAnalysisResultsArgs args = ctx.argument().orElseThrow();

        final var resultsFileMetadataSet = new HashSet<FileMetadata>(args.getResultsCount());
        final var results = new ArrayList<AnalyzeProjectVulnsResult>(args.getResultsCount());

        try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
            for (final AnalyzeProjectVulnsResult result : args.getResultsList()) {
                if (!result.hasVdrFileMetadata()) {
                    continue;
                }

                resultsFileMetadataSet.add(result.getVdrFileMetadata());

                // TODO: Fail with a terminal exception when a file was not found?
                //  Consider checking for all files first so we can report when more
                //  than one file is missing.
                LOGGER.info("Retrieving VDR file {}", result.getVdrFileMetadata().getLocation());
                final byte[] fileContent = fileStorage.get(result.getVdrFileMetadata());
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
                LOGGER.info("Deleting VDR file {}", fileMetadata.getLocation());
                fileStorage.delete(fileMetadata);
            }
        }

        return Optional.empty();
    }

}
