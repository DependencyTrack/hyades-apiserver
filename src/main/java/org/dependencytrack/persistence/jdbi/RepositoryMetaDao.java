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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.persistence.RepositoryQueryManager;
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public interface RepositoryMetaDao {

    @SqlQuery("""
            SELECT * FROM "REPOSITORY_META_COMPONENT"
                WHERE ("REPOSITORY_TYPE", "NAMESPACE", "NAME") IN (
                  SELECT *
                  FROM UNNEST(:types, :namespaces, :names)
                )
            """)
    @GetGeneratedKeys("*")
    @RegisterBeanMapper(RepositoryMetaComponent.class)
    List<RepositoryMetaComponent> getRepositoryMetaComponents(@Bind List<String> types,
                                                              @Bind List<String> namespaces,
                                                              @Bind List<String> names);

    default List<RepositoryMetaComponent> getRepositoryMetaComponents(final Set<RepositoryQueryManager.RepositoryMetaComponentSearch> list) {
        if (list == null || list.isEmpty()) {
            return Collections.emptyList();
        }
        var types = new ArrayList<String>(list.size());
        var namespaces = new ArrayList<String>(list.size());
        var names = new ArrayList<String>(list.size());
        for (var repoMeta : list) {
            types.add(repoMeta.type().name());
            namespaces.add(repoMeta.namespace());
            names.add(repoMeta.name());
        }
        return getRepositoryMetaComponents(types, namespaces, names);
    }
}
