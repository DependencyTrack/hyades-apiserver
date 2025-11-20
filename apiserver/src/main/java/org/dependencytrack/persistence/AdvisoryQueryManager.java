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
package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.Advisory;

import javax.annotation.Nullable;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;

import static org.dependencytrack.util.PersistenceUtil.applyIfChanged;

/**
 * JDO Query manager for {@link Advisory} records.
 *
 * @since 5.7.0
 */
public class AdvisoryQueryManager extends QueryManager implements IQueryManager {
    private static final Logger LOGGER = Logger.getLogger(AdvisoryQueryManager.class);

    /**
     * Constructs a new {@link AdvisoryQueryManager}.
     *
     * @param pm a PersistenceManager object
     */
    AdvisoryQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new {@link AdvisoryQueryManager}.
     *
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    AdvisoryQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Synchronizes a {{@link Advisory}}. This method first checks if the record
     * already exists and updates it. If it does exist, it will create a new record.
     *
     * @param advisory The advisory to synchronize
     * @return an advisory entity
     */
    public Advisory synchronizeAdvisory(Advisory advisory) {
        Advisory result = updateAdvisory(advisory);
        if (result == null) {
            return pm.makePersistent(advisory);
        }

        return result;
    }

    /**
     * Retrieves a specific advisory by its publisher namespace and name, which makes it unique.
     *
     * @param publisher the publisher namespace
     * @param name         the name
     * @return the advisory entity (or null if it does not exist)
     */
    public @Nullable Advisory getAdvisoryByPublisherAndName(String publisher, String name) {
        final Query<Advisory> query = pm.newQuery(Advisory.class, "publisher == :publisher && name == :name");
        query.setRange(0, 1);

        return singleResult(query.execute(publisher, name));
    }

    /**
     * Updates an existing advisory.
     *
     * @param advisory The advisory entity to update
     * @return the updated advisory entity
     */
    public Advisory updateAdvisory(Advisory advisory) {
        final Advisory existing = getAdvisoryByPublisherAndName(advisory.getPublisher(), advisory.getName());
        if (existing != null) {
            applyIfChanged(existing, advisory, Advisory::getTitle, existing::setTitle);
            applyIfChanged(existing, advisory, Advisory::getUrl, existing::setUrl);
            applyIfChanged(existing, advisory, Advisory::getContent, existing::setContent);
            applyIfChanged(existing, advisory, Advisory::isSeen, existing::setSeen);
            applyIfChanged(existing, advisory, Advisory::getPublisher, existing::setPublisher);
            applyIfChanged(existing, advisory, Advisory::getName, existing::setName);
            applyIfChanged(existing, advisory, Advisory::getVersion, existing::setVersion);
            applyIfChanged(existing, advisory, Advisory::getFormat, existing::setFormat);
            applyIfChanged(existing, advisory, Advisory::getLastFetched, existing::setLastFetched);
            return existing;
        }

        return null;
    }

}
