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
package org.dependencytrack.secret;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretManagerFactory;
import org.dependencytrack.secret.management.cache.CachingSecretManager;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ServiceLoader;

/**
 * @since 5.7.0
 */
public final class SecretManagerInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecretManagerInitializer.class);

    public static SecretManager INSTANCE;

    private final Config config;

    SecretManagerInitializer(final Config config) {
        this.config = config;
    }

    @SuppressWarnings("unused")
    public SecretManagerInitializer() {
        this(ConfigProvider.getConfig());
    }

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        final String providerName = config.getValue("dt.secret-management.provider", String.class);
        final var secretManagerFactory = ServiceLoader.load(SecretManagerFactory.class).stream()
                .map(ServiceLoader.Provider::get)
                .filter(factory -> providerName.equals(factory.name()))
                .findAny()
                .orElseThrow(() -> new IllegalStateException(
                        "No secret management provider found for name: " + providerName));

        LOGGER.info("Initializing secret management provider: {}", secretManagerFactory.name());
        INSTANCE = CachingSecretManager.maybeWrap(secretManagerFactory.create(), config);
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        if (INSTANCE != null) {
            LOGGER.info("Closing secret manager");
            INSTANCE.close();
            INSTANCE = null;
        }
    }

}
