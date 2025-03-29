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

import java.util.List;

import org.jdbi.v3.sqlobject.config.RegisterFieldMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.customizer.DefineNamedBindings;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import alpine.model.Permission;
import alpine.model.UserPrincipal;

/**
 * @since 5.6.0
 */
public interface EffectivePermissionDao {

    @SqlQuery(/* language=sql */ """
            <#-- @ftlvariable name="userClass" type="java.lang.Class<? extends alpine.model.UserPrincipal>" -->
            <#assign prefix = userClass.getSimpleName()?upper_case>
            SELECT
                p."ID",
                p."NAME",
                p."DESCRIPTION"
              FROM "USER_PROJECT_EFFECTIVE_PERMISSIONS" upep
             INNER JOIN "PERMISSION" p
                ON upep."PERMISSION_ID" = p."ID"
             WHERE upep."${prefix}_ID" = :userId
               AND upep."PROJECT_ID" = :projectId
            """)
    @DefineNamedBindings
    @RegisterFieldMapper(Permission.class)
    <T extends UserPrincipal> List<Permission> getEffectivePermissions(
            @Define Class<T> userClass,
            @Bind Long userId,
            @Bind Long projectId);

}
