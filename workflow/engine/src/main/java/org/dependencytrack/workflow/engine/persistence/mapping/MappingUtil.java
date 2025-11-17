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
package org.dependencytrack.workflow.engine.persistence.mapping;

import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.Map;

import static org.jdbi.v3.core.generic.GenericTypes.parameterizeClass;

final class MappingUtil {

    private MappingUtil() {
    }

    @SuppressWarnings("unchecked")
    static <K, V> Map<K, V> mapJsonEncodedMap(
            final ResultSet rs,
            final StatementContext ctx,
            final String columnName,
            final Class<K> keyClass,
            final Class<V> valueClass) throws SQLException {
        final String labelsJson = rs.getString(columnName);
        if (rs.wasNull()) {
            return Collections.emptyMap();
        }

        final JsonMapper.TypedJsonMapper jsonMapper = ctx
                .getConfig(JsonConfig.class).getJsonMapper()
                .forType(parameterizeClass(Map.class, keyClass, valueClass), ctx.getConfig());

        return (Map<K, V>) jsonMapper.fromJson(labelsJson, ctx.getConfig());
    }

}
