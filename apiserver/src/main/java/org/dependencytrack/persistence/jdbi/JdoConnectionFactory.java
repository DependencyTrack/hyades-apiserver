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

import net.jcip.annotations.NotThreadSafe;
import org.jdbi.v3.core.ConnectionFactory;

import javax.jdo.PersistenceManager;
import javax.jdo.datastore.JDOConnection;
import java.sql.Connection;

@NotThreadSafe
class JdoConnectionFactory implements ConnectionFactory {

    private final PersistenceManager pm;
    private JDOConnection jdoConnection;

    JdoConnectionFactory(final PersistenceManager pm) {
        this.pm = pm;
    }

    @Override
    public Connection openConnection() {
        if (jdoConnection != null) {
            throw new IllegalStateException("A JDO connection is already open");
        }

        jdoConnection = pm.getDataStoreConnection();
        return (Connection) jdoConnection.getNativeConnection();
    }

    @Override
    public void closeConnection(final Connection conn) {
        jdoConnection.close();
        jdoConnection = null;
    }

}
