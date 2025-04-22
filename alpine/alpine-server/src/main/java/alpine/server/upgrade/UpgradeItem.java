/*
 * This file is part of Alpine.
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
package alpine.server.upgrade;

import alpine.persistence.AlpineQueryManager;

import java.sql.Connection;
import java.sql.SQLException;

public interface UpgradeItem {

    // Returns the version of the database schema that represents the structure of the database after the upgrade has run
    // Basically, the version of the database schema that the changes that the upgrade class implements
    String getSchemaVersion();

    boolean shouldUpgrade(AlpineQueryManager queryManager, Connection connection) throws SQLException;

    void executeUpgrade(AlpineQueryManager queryManager, Connection connection) throws Exception;
}