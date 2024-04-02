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
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.persistence.QueryManager;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;

public class NistMirrorTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(NistMirrorTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof NistMirrorEvent) {
            try (final QueryManager qm = new QueryManager()) {
                final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_NVD_ENABLED.getGroupName(), VULNERABILITY_SOURCE_NVD_ENABLED.getPropertyName());
                final boolean isEnabled = enabled != null && Boolean.valueOf(enabled.getPropertyValue());
                if (!isEnabled) {
                    return;
                }

                final long start = System.currentTimeMillis();
                LOGGER.info("Starting NIST mirroring task");
                new KafkaEventDispatcher().dispatchEvent(new NistMirrorEvent()).join();
                final long end = System.currentTimeMillis();
                LOGGER.info("NIST mirroring complete. Time spent (total): " + (end - start) + "ms");
            } catch (Exception ex) {
                LOGGER.error("An unexpected error occurred while triggering NIST mirroring", ex);
            }
        }
    }
}