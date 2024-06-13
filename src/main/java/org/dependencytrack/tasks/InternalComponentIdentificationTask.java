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
import alpine.event.framework.Subscriber;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockExtender;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.dependencytrack.event.InternalComponentIdentificationEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.InternalComponentIdentifier;
import org.dependencytrack.util.LockProvider;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.Transaction;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.dependencytrack.tasks.LockName.INTERNAL_COMPONENT_IDENTIFICATION_TASK_LOCK;
import static org.dependencytrack.util.LockProvider.isLockToBeExtended;

/**
 * Subscriber task that identifies internal components throughout the entire portfolio.
 *
 * @author nscuro
 * @since 3.7.0
 */
public class InternalComponentIdentificationTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(InternalComponentIdentificationTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof InternalComponentIdentificationEvent) {
            try {
                LockProvider.executeWithLock(INTERNAL_COMPONENT_IDENTIFICATION_TASK_LOCK, (LockingTaskExecutor.Task) this::analyze);
            } catch (Throwable ex) {
                LOGGER.error("Error in acquiring lock and executing internal component identification task", ex);
            }
        }
    }

    private void analyze() throws Exception {
        final Instant startTime = Instant.now();
        LOGGER.info("Starting internal component identification");
        LockConfiguration lockConfiguration = LockProvider.getLockConfigurationByLockName(INTERNAL_COMPONENT_IDENTIFICATION_TASK_LOCK);
        try (final var qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            final var internalComponentIdentifier = new InternalComponentIdentifier();
            List<Component> components = fetchNextComponentsPage(pm, null);
            while (!components.isEmpty()) {
                //Extend the lock by 5 min everytime we have a page.
                //We will get max 1000 components in a page
                //Reason of not extending at the end of loop is if it does not have to do much,
                //It might finish execution before lock could be extended resulting in error
                LOGGER.debug("extending lock of internal component identification by 5 min");
                long cumulativeProcessingDuration = System.currentTimeMillis() - startTime.toEpochMilli();
                if(isLockToBeExtended(cumulativeProcessingDuration, INTERNAL_COMPONENT_IDENTIFICATION_TASK_LOCK)) {
                    LockExtender.extendActiveLock(Duration.ofMinutes(5).plus(lockConfiguration.getLockAtLeastFor()), lockConfiguration.getLockAtLeastFor());
                }
                for (final Component component : components) {
                    String coordinates = component.getName();
                    if (StringUtils.isNotBlank(component.getGroup())) {
                        coordinates = component.getGroup() + ":" + coordinates;
                    }

                    final boolean internal = internalComponentIdentifier.isInternal(component);;
                    if (internal) {
                        LOGGER.debug("Component " + coordinates + " (" + component.getUuid() + ") was identified to be internal");
                    }

                    if (component.isInternal() != internal) {
                        if (internal) {
                            LOGGER.info("Component " + coordinates + " (" + component.getUuid()
                                    + ") was identified to be internal. It was previously not an internal component.");
                        } else {
                            LOGGER.info("Component " + coordinates + " (" + component.getUuid()
                                    + ") was previously identified as internal. It is no longer identified as internal.");
                        }
                    }

                    if (component.isInternal() != internal) {
                        final Transaction trx = pm.currentTransaction();
                        try {
                            trx.begin();
                            component.setInternal(internal);
                            trx.commit();
                        } finally {
                            if (trx.isActive()) {
                                trx.rollback();
                            }
                        }
                    }
                }

                final long lastId = components.getLast().getId();
                components = fetchNextComponentsPage(pm, lastId);
            }
        }
        LOGGER.info("Internal component identification completed in "
                + DateFormatUtils.format(Duration.between(startTime, Instant.now()).toMillis(), "mm:ss:SS"));
    }

    /**
     * Efficiently page through all components using keyset pagination.
     *
     * @param pm     The {@link PersistenceManager} to use
     * @param lastId ID of the last {@link Component} in the previous result set, or {@code null} if this is the first invocation
     * @return A {@link List} representing a page of up to {@code 500} {@link Component}s
     * @throws Exception When closing the query failed
     * @see <a href="https://use-the-index-luke.com/no-offset">Keyset pagination</a>
     */
    private List<Component> fetchNextComponentsPage(final PersistenceManager pm, final Long lastId) throws Exception {
        try (final Query<Component> query = pm.newQuery(Component.class)) {
            if (lastId != null) {
                query.setFilter("id < :lastId");
                query.setParameters(lastId);
            }
            query.setOrdering("id DESC");
            query.setRange(0, 1000);
            query.getFetchPlan().setGroup(Component.FetchGroup.INTERNAL_IDENTIFICATION.name());
            return List.copyOf(query.executeList());
        }
    }

}
