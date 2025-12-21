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

import alpine.resources.AlpineRequest;
import org.dependencytrack.model.Advisory;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.Map;

import static org.dependencytrack.util.PersistenceUtil.applyIfChanged;

/**
 * JDO Query manager for {@link Advisory} records.
 *
 * @since 5.7.0
 */
@NullMarked
public class AdvisoryQueryManager extends QueryManager implements IQueryManager {

    AdvisoryQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    AdvisoryQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    @Override
    public @Nullable Advisory synchronizeAdvisory(Advisory advisory) {
        Advisory result = updateAdvisory(advisory);
        if (result == null) {
            result = createAdvisory(advisory);
        }

        return result;
    }

    private @Nullable Advisory getAdvisoryByPublisherAndName(String publisher, String name) {
        final Query<@Nullable Advisory> query = pm.newQuery(Advisory.class, "publisher == :publisher && name == :name");
        query.setNamedParameters(Map.ofEntries(
                Map.entry("publisher", publisher),
                Map.entry("name", name)));
        return executeAndCloseUnique(query);
    }

    private Advisory createAdvisory(Advisory transientAdvisory) {
        final var advisory = new Advisory();
        advisory.setPublisher(transientAdvisory.getPublisher());
        advisory.setName(transientAdvisory.getName());
        advisory.setVersion(transientAdvisory.getVersion());
        advisory.setFormat(transientAdvisory.getFormat());
        advisory.setTitle(transientAdvisory.getTitle());
        advisory.setUrl(transientAdvisory.getUrl());
        advisory.setContent(transientAdvisory.getContent());
        advisory.setLastFetched(transientAdvisory.getLastFetched());
        advisory.setSeenAt(transientAdvisory.getSeenAt());
        return pm.makePersistent(advisory);
    }

    private @Nullable Advisory updateAdvisory(Advisory advisory) {
        final Advisory existing = getAdvisoryByPublisherAndName(advisory.getPublisher(), advisory.getName());
        if (existing != null) {
            applyIfChanged(existing, advisory, Advisory::getTitle, existing::setTitle);
            applyIfChanged(existing, advisory, Advisory::getUrl, existing::setUrl);
            applyIfChanged(existing, advisory, Advisory::getContent, existing::setContent);
            applyIfChanged(existing, advisory, Advisory::getSeenAt, existing::setSeenAt);
            applyIfChanged(existing, advisory, Advisory::getVersion, existing::setVersion);
            applyIfChanged(existing, advisory, Advisory::getFormat, existing::setFormat);
            applyIfChanged(existing, advisory, Advisory::getLastFetched, existing::setLastFetched);
            return existing;
        }

        return null;
    }

}
