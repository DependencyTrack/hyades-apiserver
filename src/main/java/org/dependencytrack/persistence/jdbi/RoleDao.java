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

import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

/**
 * @since 5.6.0
 */
public interface RoleDao {

    @SqlUpdate(/* language=sql */ """
            DELETE
              FROM "ROLE"
             WHERE "ID" = :roleId
            """)
    int deleteRole(@Bind final long roleId);

    @SqlUpdate(/* language=sql */ """
        DELETE
          FROM "LDAPUSERS_PROJECTS_ROLES"
         WHERE "LDAPUSER_ID" = :userId
           AND "PROJECT_ACCESS_ROLE_ID" IN (
               SELECT "ID"
                 FROM "PROJECT_ACCESS_ROLES"
                WHERE "ROLE_ID" = :roleId
                  AND "PROJECT_ID" = :projectId)
        """)
    int removeRoleFromLdapUser(@Bind final long userId, @Bind final long projectId, @Bind final long roleId);

    @SqlUpdate(/* language=sql */ """
        DELETE
          FROM "MANAGEDUSERS_PROJECTS_ROLES"
         WHERE "MANAGEDUSER_ID" = :userId
           AND "PROJECT_ACCESS_ROLE_ID" IN (
               SELECT "ID"
                 FROM "PROJECT_ACCESS_ROLES"
                WHERE "ROLE_ID" = :roleId
                  AND "PROJECT_ID" = :projectId)
        """)
    int removeRoleFromManagedUser(@Bind final long userId, @Bind final long projectId, @Bind final long roleId);

    @SqlUpdate(/* language=sql */ """
            DELETE
              FROM "OIDCUSERS_PROJECTS_ROLES"
             WHERE "OIDCUSER_ID" = :userId
               AND "PROJECT_ACCESS_ROLE_ID" IN (
                   SELECT "ID"
                     FROM "PROJECT_ACCESS_ROLES"
                    WHERE "ROLE_ID" = :roleId
                      AND "PROJECT_ID" = :projectId)
            """)
    int removeRoleFromOidcUser(@Bind final long userId, @Bind final long projectId, @Bind final long roleId);

}
