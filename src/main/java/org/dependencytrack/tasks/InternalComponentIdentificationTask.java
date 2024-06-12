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
import org.jdbi.v3.core.statement.PreparedBatch;
import org.jdbi.v3.core.statement.SqlStatements;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.jdbi;
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

    private void analyze() {
        final Instant startTime = Instant.now();
        LOGGER.info("Starting internal component identification");
        LockConfiguration lockConfiguration = LockProvider.getLockConfigurationByLockName(INTERNAL_COMPONENT_IDENTIFICATION_TASK_LOCK);
        final var internalComponentIdentifier = new InternalComponentIdentifier();

        try (final var qm = new QueryManager()) {
            if (!internalComponentIdentifier.hasPatterns() && !internalComponentsExist(qm)) {
                LOGGER.debug("""
                        No internal patterns configured, and no components currently
                        marked as internal exist; Nothing to do""");
                return;
            }

            final var changedInternalStatusByComponentId = new HashMap<Long, Boolean>(250);
            List<Component> components = fetchNextComponentsPage(qm, null);
            while (!components.isEmpty()) {
                //Extend the lock by 5 min everytime we have a page.
                //We will get max 1000 components in a page
                //Reason of not extending at the end of loop is if it does not have to do much,
                //It might finish execution before lock could be extended resulting in error
                LOGGER.debug("extending lock of internal component identification by 5 min");
                long cumulativeProcessingDuration = System.currentTimeMillis() - startTime.toEpochMilli();
                if (isLockToBeExtended(cumulativeProcessingDuration, INTERNAL_COMPONENT_IDENTIFICATION_TASK_LOCK)) {
                    LockExtender.extendActiveLock(Duration.ofMinutes(5).plus(lockConfiguration.getLockAtLeastFor()), lockConfiguration.getLockAtLeastFor());
                }

                for (final Component component : components) {
                    String coordinates = component.getName();
                    if (StringUtils.isNotBlank(component.getGroup())) {
                        coordinates = component.getGroup() + ":" + coordinates;
                    }

                    final boolean internal = internalComponentIdentifier.isInternal(component);
                    if (internal && LOGGER.isDebugEnabled()) {
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

                        changedInternalStatusByComponentId.put(component.getId(), internal);
                    }
                }

                updateInternalStatuses(qm, changedInternalStatusByComponentId);
                changedInternalStatusByComponentId.clear();

                final long lastId = components.getLast().getId();
                components = fetchNextComponentsPage(qm, lastId);
            }
        }
        LOGGER.info("Internal component identification completed in "
                + DateFormatUtils.format(Duration.between(startTime, Instant.now()).toMillis(), "mm:ss:SS"));
    }

    private boolean internalComponentsExist(final QueryManager qm) {
        return jdbi(qm).withHandle(handle -> handle.createQuery("""
                        SELECT EXISTS(SELECT 1 FROM "COMPONENT" WHERE "INTERNAL")
                        """)
                .mapTo(Boolean.class)
                .one());
    }

    private List<Component> fetchNextComponentsPage(final QueryManager qm, final Long lastId) {
        return jdbi(qm).withHandle(handle -> handle.createQuery(/* language=InjectedFreeMarker */ """
                        <#-- @ftlvariable name="lastId" type="boolean" -->
                        SELECT "ID"
                             , "GROUP"
                             , "NAME"
                             , "INTERNAL"
                             , "UUID"
                          FROM "COMPONENT"
                        <#if lastId>
                         WHERE "ID" < :lastId
                        </#if>
                         ORDER BY "ID" DESC
                         FETCH NEXT 1000 ROWS ONLY
                        """)
                // lastId parameter is not bound for first iteration.
                .configure(SqlStatements.class, cfg -> cfg.setUnusedBindingAllowed(true))
                .bind("lastId", lastId)
                .defineNamedBindings()
                .mapToBean(Component.class)
                .list());
    }

    private void updateInternalStatuses(final QueryManager qm, final Map<Long, Boolean> internalStatusByComponentId) {
        if (internalStatusByComponentId.isEmpty()) {
            return;
        }

        jdbi(qm).useTransaction(handle -> {
            final PreparedBatch batch = handle.prepareBatch("""
                    UPDATE "COMPONENT"
                       SET "INTERNAL" = :internal
                     WHERE "ID" = :id
                    """);

            internalStatusByComponentId.forEach((componentId, internalStatus) -> {
                batch.bind("id", componentId);
                batch.bind("internal", internalStatus);
                batch.add();
            });

            batch.execute();
        });
    }

}
