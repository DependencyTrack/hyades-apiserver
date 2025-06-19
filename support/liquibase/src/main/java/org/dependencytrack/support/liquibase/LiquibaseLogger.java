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
package org.dependencytrack.support.liquibase;

import liquibase.logging.core.AbstractLogService;
import liquibase.logging.core.AbstractLogger;
import liquibase.plugin.Plugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.logging.Level;

/**
 * @since 5.5.0
 */
class LiquibaseLogger extends AbstractLogger {

    private final Logger logger;

    LiquibaseLogger(final Class<?> clazz) {
        this.logger = LoggerFactory.getLogger(clazz);
    }

    @Override
    public void log(final Level level, final String message, final Throwable e) {
        if (Level.SEVERE.equals(level)) {
            logger.error(message, e);
        } else if (Level.WARNING.equals(level)) {
            logger.warn(message, e);
        } else if (Level.INFO.equals(level)) {
            logger.info(message, e);
        } else if (Level.CONFIG.equals(level) || Level.FINE.equals(level)) {
            logger.debug(message, e);
        } else if (Level.FINER.equals(level) || Level.FINEST.equals(level)) {
            logger.trace(message, e);
        }
    }

    static class LogService extends AbstractLogService {

        @Override
        public int getPriority() {
            return Plugin.PRIORITY_SPECIALIZED;
        }

        @Override
        public liquibase.logging.Logger getLog(final Class clazz) {
            return new LiquibaseLogger(clazz);
        }

    }

}
