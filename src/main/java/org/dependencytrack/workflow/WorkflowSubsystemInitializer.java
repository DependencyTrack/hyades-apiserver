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

import alpine.common.logging.Logger;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import java.io.IOException;

public class WorkflowSubsystemInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(WorkflowSubsystemInitializer.class);

    private WorkflowEngine workflowEngine;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing workflow engine");
        workflowEngine = WorkflowEngine.getInstance();
        workflowEngine.start();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Shutting down workflow engine");

        try {
            workflowEngine.close();
        } catch (IOException | RuntimeException e) {
            LOGGER.warn("Graceful shutdown of workflow engine failed", e);
        }
    }
}
