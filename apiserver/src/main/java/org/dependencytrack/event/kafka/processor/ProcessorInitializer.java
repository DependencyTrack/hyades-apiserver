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
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.common.health.HealthCheckRegistry;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.event.kafka.processor.api.ProcessorManager;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.policy.cel.CelVulnerabilityPolicyEvaluator;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.common.ConfigKey.VULNERABILITY_POLICY_ANALYSIS_ENABLED;

public class ProcessorInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(ProcessorInitializer.class);

    private final Config config = ConfigProvider.getConfig();
    private ProcessorManager processorManager;

    @Override
    public void contextInitialized(ServletContextEvent event) {
        LOGGER.info("Initializing processors");

        final ServletContext servletContext = event.getServletContext();

        final var pluginManager = (PluginManager) servletContext.getAttribute(PluginManager.class.getName());
        requireNonNull(pluginManager, "pluginManager has not been initialized");

        final var healthCheckRegistry = (HealthCheckRegistry) servletContext.getAttribute(HealthCheckRegistry.class.getName());
        requireNonNull(healthCheckRegistry, "healthCheckRegistry has not been initialized");

        processorManager = new ProcessorManager();
        processorManager.registerProcessor(RepositoryMetaResultProcessor.PROCESSOR_NAME,
                KafkaTopics.REPO_META_ANALYSIS_RESULT, new RepositoryMetaResultProcessor());
        processorManager.registerProcessor(
                VulnerabilityScanResultProcessor.PROCESSOR_NAME,
                KafkaTopics.VULN_ANALYSIS_RESULT,
                new VulnerabilityScanResultProcessor(
                        pluginManager,
                        config.getOptionalValue(VULNERABILITY_POLICY_ANALYSIS_ENABLED.getPropertyName(), boolean.class).orElse(false)
                                ? new CelVulnerabilityPolicyEvaluator()
                                : null));
        processorManager.registerBatchProcessor(ProcessedVulnerabilityScanResultProcessor.PROCESSOR_NAME,
                KafkaTopics.VULN_ANALYSIS_RESULT_PROCESSED, new ProcessedVulnerabilityScanResultProcessor());

        healthCheckRegistry.addCheck(new ProcessorsHealthCheck(processorManager));
        processorManager.startAll();
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        if (processorManager != null) {
            LOGGER.info("Stopping processors");
            processorManager.close();
        }
    }

}
