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
import org.dependencytrack.job.JobManager;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import java.io.IOException;

public class WorkflowSubsystemInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(WorkflowSubsystemInitializer.class);

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing workflow engine");
        final var workflowEngine = WorkflowEngine.getInstance();
        JobManager.getInstance().registerStatusListener(workflowEngine);
        workflowEngine.deploy(Workflows.WORKFLOW_BOM_UPLOAD_PROCESSING_V1);
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Shutting down workflow engine");

        try {
            WorkflowEngine.getInstance().close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
