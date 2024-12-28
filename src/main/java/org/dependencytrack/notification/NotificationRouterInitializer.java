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
package org.dependencytrack.notification;

import alpine.Config;
import org.dependencytrack.common.ConfigKey;
import org.postgresql.ds.PGSimpleDataSource;
import org.postgresql.jdbc.PreferQueryMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

public class NotificationRouterInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationRouterInitializer.class);

    private NotificationRouter router;

    @Override
    public void contextInitialized(final ServletContextEvent sce) {
        if (Config.getInstance().getPropertyAsBoolean(ConfigKey.INIT_AND_EXIT)) {
            return;
        }
        if (!Config.getInstance().getPropertyAsBoolean(ConfigKey.WORKFLOW_ENGINE_ENABLED)) {
            return;
        }

        // TODO: This needs a non-pooled connection because Postgres requires
        //  a special connection type for logical replication that a normal pool
        //  cannot provide. It's likely we need to offer a separate URL config
        //  so users can bypass their PgBouncer.
        // TODO: Consuming from a replication slot requires the REPLICATION permission.
        //  Users may want to limit this permission to certain accounts, so we'd need to
        //  allow passing of specific credentials for this purpose.
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(Config.getInstance().getProperty(Config.AlpineKey.DATABASE_URL));
        dataSource.setUser(Config.getInstance().getProperty(Config.AlpineKey.DATABASE_USERNAME));
        dataSource.setPassword(Config.getInstance().getProperty(Config.AlpineKey.DATABASE_PASSWORD));
        dataSource.setReplication("database");
        dataSource.setPreferQueryMode(PreferQueryMode.SIMPLE);
        dataSource.setAssumeMinServerVersion("14");

        LOGGER.info("Starting notification router");
        router = new NotificationRouter(dataSource);
        router.start();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent sce) {
        if (router != null) {
            LOGGER.info("Stopping notification router");
            router.close();
        }
    }
}
