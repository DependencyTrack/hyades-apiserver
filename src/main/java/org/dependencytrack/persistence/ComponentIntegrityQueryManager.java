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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.persistence;

import alpine.resources.AlpineRequest;
import org.dependencytrack.model.ComponentIntegrityAnalysis;

import javax.jdo.JDODataStoreException;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.Transaction;
import java.util.UUID;

public class ComponentIntegrityQueryManager extends QueryManager implements IQueryManager {

    /**
     * Constructs a new QueryManager.
     *
     * @param pm a PersistenceManager object
     */
    ComponentIntegrityQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    ComponentIntegrityQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    public ComponentIntegrityAnalysis getIntegrityAnalysisComponentResult(UUID uuid, String repositoryIdentifier, double componentId) {
        ComponentIntegrityAnalysis persistentIntegrityResult;
        final Transaction trx = pm.currentTransaction();
        try {
            trx.begin();
            final Query<ComponentIntegrityAnalysis> query = pm.newQuery(ComponentIntegrityAnalysis.class);
            query.setFilter("repositoryIdentifier == :repository && component.id == :id && component.uuid == :uuid");
            query.setParameters(
                    repositoryIdentifier,
                    componentId,
                    uuid
            );
            persistentIntegrityResult = query.executeUnique();
            trx.commit();
        } catch (JDODataStoreException ex) {
            throw ex;
        }
        return persistentIntegrityResult;
    }


}
