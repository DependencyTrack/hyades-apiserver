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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;

import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.Project;

import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import jakarta.validation.constraints.NotNull;

public class CryptoAssetQueryManager extends QueryManager implements IQueryManager {

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    CryptoAssetQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    CryptoAssetQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a complete list of all CryptoAssets
     * @return a List of CryptoAssets
     */
    @SuppressWarnings("unchecked")
    public List<Component> getAllCryptoAssets() {
        final Query<Component> query = pm.newQuery(Component.class, "(classifier == :asset)");
        query.getFetchPlan().setMaxFetchDepth(3);
        return (List<Component>) query.execute(Classifier.CRYPTOGRAPHIC_ASSET);
    }

    /**
     * Returns a List of all CryptoAssets for the specified Project.
     * This method is designed NOT to provide paginated results.
     * @param project the Project to retrieve dependencies of
     * @return a List of Component objects
     */
    @SuppressWarnings("unchecked")
    public List<Component> getAllCryptoAssets(Project project) {
        final Query<Component> query = pm.newQuery(Component.class, "(project == :project) && (classifier == :asset)");
        query.getFetchPlan().setMaxFetchDepth(3);
        query.setOrdering("name asc");
        return (List<Component>)query.execute(project, Classifier.CRYPTOGRAPHIC_ASSET);
    }

    /**
     * Returns crypto assets by their identity.
     * @param identity the asset identity to query against
     * @return a list of components
     */
    public PaginatedResult getCryptoAssets(@NotNull ComponentIdentity identity) {
        Pair<ArrayList<String>, HashMap<String, Object>> queryProp = buildIdentityQuery(identity);
        String filter = String.join(" && ", queryProp.getKey());
        return loadComponents(filter, queryProp.getValue());
    }

    private PaginatedResult loadComponents(String queryFilter, Map<String, Object> params) {
        var query = pm.newQuery(Component.class);
        query.getFetchPlan().setMaxFetchDepth(3);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        preprocessACLs(query, queryFilter, params, false);
        return execute(query, params);
    }

    private Pair<ArrayList<String>, HashMap<String, Object>> buildIdentityQuery(@NotNull ComponentIdentity identity) {
        final var queryFilterElements = new ArrayList<String>();
        final var queryParams = new HashMap<String, Object>();

        queryFilterElements.add(" classifier == :classifier ");
        queryParams.put("classifier", Classifier.CRYPTOGRAPHIC_ASSET);

        if (identity.getAssetType() != null) {
            try {
                queryFilterElements.add("cryptoAssetProperties.assetType == :assetType");
                queryParams.put("assetType", identity.getAssetType());
            } catch (IllegalArgumentException iae) {
            // ignore
            }
        }

        return Pair.of(queryFilterElements, queryParams);
    }
}
