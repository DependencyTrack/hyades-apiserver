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
package org.dependencytrack.common;

import alpine.common.logging.Logger;
import alpine.security.crypto.KeyManager;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

/**
 * @since 5.6.0
 */
public class KeyManagerInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(KeyManagerInitializer.class);

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing KeyManager");

        // Force initialization of KeyManager, which will cause
        // the secret, as well as the public-private key pair
        // to be generated if necessary.
        final var ignored = KeyManager.getInstance();
    }

}
