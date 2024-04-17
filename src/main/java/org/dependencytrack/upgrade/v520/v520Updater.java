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
package org.dependencytrack.upgrade.v520;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class v520Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v520Updater.class);

    @Override
    public String getSchemaVersion() {
        return "5.2.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        changePurlColumnLengthInIntegrityMetaComponentTable(connection);
        dropStatusCheckConstraintOnIntegrityMetaComponentTable(connection);
    }

    private static void changePurlColumnLengthInIntegrityMetaComponentTable(final Connection connection) throws Exception {
        LOGGER.info("Changing length of \"PURL\" from VARCHAR(255) to VARCHAR(1024)");
        try (final PreparedStatement ps = connection.prepareStatement("""
                	ALTER TABLE "INTEGRITY_META_COMPONENT" ALTER "PURL" TYPE VARCHAR(1024);
                """)) {
            ps.execute();
        }
    }

    private static void dropStatusCheckConstraintOnIntegrityMetaComponentTable(final Connection connection) throws Exception {
        LOGGER.info("Dropping constraint \"INTEGRITY_META_COMPONENT_STATUS_check\" if it exists on \"INTEGRITY_META_COMPONENT\" table");
        try (final PreparedStatement ps = connection.prepareStatement("""
                	ALTER TABLE "INTEGRITY_META_COMPONENT" DROP CONSTRAINT IF EXISTS "INTEGRITY_META_COMPONENT_STATUS_check" RESTRICT;
                """)) {
            ps.execute();
        }
    }
}
