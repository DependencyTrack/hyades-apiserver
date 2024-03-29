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
package org.dependencytrack.common;

import alpine.Config;
import alpine.model.ConfigProperty;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.Query;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

public final class ClusterInfo {

    private static final Supplier<String> CLUSTER_ID_SUPPLIER = Suppliers.memoize(ClusterInfo::loadClusterId);

    public static String getClusterId() {
        return CLUSTER_ID_SUPPLIER.get();
    }

    private static String loadClusterId() {
        if (Config.isUnitTestsEnabled()) {
            return UUID.randomUUID().toString();
        }

        try (final var qm = new QueryManager()) {
            final Query<ConfigProperty> query = qm.getPersistenceManager().newQuery(ConfigProperty.class);
            query.setFilter("groupName == :groupName && propertyName == :propertyName");
            query.setParameters(
                    ConfigPropertyConstants.INTERNAL_CLUSTER_ID.getGroupName(),
                    ConfigPropertyConstants.INTERNAL_CLUSTER_ID.getPropertyName()
            );
            query.setResult("propertyValue");

            try {
                final String clusterId = query.executeResultUnique(String.class);
                return requireNonNull(clusterId, "Cluster ID must not be null");
            } finally {
                query.closeAll();
            }
        }
    }

}
