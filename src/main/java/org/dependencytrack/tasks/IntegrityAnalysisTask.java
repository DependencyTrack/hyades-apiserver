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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.IntegrityAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;

import java.util.UUID;

import static org.dependencytrack.event.kafka.componentmeta.IntegrityCheck.calculateIntegrityResult;

public class IntegrityAnalysisTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(IntegrityAnalysisTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof final IntegrityAnalysisEvent event) {
            if (!Config.getInstance().getPropertyAsBoolean(ConfigKey.INTEGRITY_CHECK_ENABLED)) {
                return;
            }
            LOGGER.debug("Performing integrity analysis for component: " + event.getUuid());
            if(event.getUuid() == null) {
                return;
            }
            try (final var qm = new QueryManager()) {
                UUID uuid = event.getUuid();
                IntegrityMetaComponent integrityMetaComponent = event.getIntegrityMetaComponent();
                Component component = qm.getObjectByUuid(Component.class, uuid);
                calculateIntegrityResult(integrityMetaComponent, component, qm);
            }
        }
    }
}
