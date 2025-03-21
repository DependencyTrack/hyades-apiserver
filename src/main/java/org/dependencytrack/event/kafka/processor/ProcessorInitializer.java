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
package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.event.kafka.processor.api.ProcessorManager;

public class ProcessorInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(ProcessorInitializer.class);

    static final ProcessorManager PROCESSOR_MANAGER = new ProcessorManager();

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing processors");

        PROCESSOR_MANAGER.registerProcessor(VulnerabilityMirrorProcessor.PROCESSOR_NAME,
                KafkaTopics.NEW_VULNERABILITY, new VulnerabilityMirrorProcessor());
        PROCESSOR_MANAGER.registerProcessor(RepositoryMetaResultProcessor.PROCESSOR_NAME,
                KafkaTopics.REPO_META_ANALYSIS_RESULT, new RepositoryMetaResultProcessor());
        PROCESSOR_MANAGER.registerBatchProcessor(EpssMirrorProcessor.PROCESSOR_NAME,
                KafkaTopics.NEW_EPSS, new EpssMirrorProcessor());
        PROCESSOR_MANAGER.registerBatchProcessor(CsafMirrorProcessor.PROCESSOR_NAME,
                KafkaTopics.NEW_CSAF_DOCUMENT, new CsafMirrorProcessor());
        PROCESSOR_MANAGER.registerProcessor(VulnerabilityScanResultProcessor.PROCESSOR_NAME,
                KafkaTopics.VULN_ANALYSIS_RESULT, new VulnerabilityScanResultProcessor());
        PROCESSOR_MANAGER.registerBatchProcessor(ProcessedVulnerabilityScanResultProcessor.PROCESSOR_NAME,
                KafkaTopics.VULN_ANALYSIS_RESULT_PROCESSED, new ProcessedVulnerabilityScanResultProcessor());

        PROCESSOR_MANAGER.startAll();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Stopping processors");
        PROCESSOR_MANAGER.close();
    }

}
