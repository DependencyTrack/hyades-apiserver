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
package org.dependencytrack.context;

import org.glassfish.hk2.utilities.binding.AbstractBinder;

import jakarta.inject.Singleton;
import jakarta.ws.rs.ext.Provider;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;

@Provider
public class PersistenceManagerFactoryBinder extends AbstractBinder {

    @Override
    protected void configure() {
        bindFactory(Factory.class).to(PersistenceManagerFactory.class).in(Singleton.class);
    }

    private static class Factory implements org.glassfish.hk2.api.Factory<PersistenceManagerFactory> {

        @Override
        public PersistenceManagerFactory provide() {
            // TODO: Eventually PMF construction should happen here.

            try (final PersistenceManager pm = alpine.server.persistence.PersistenceManagerFactory.createPersistenceManager()) {
                return pm.getPersistenceManagerFactory();
            }
        }

        @Override
        public void dispose(final PersistenceManagerFactory instance) {
        }

    }

}
