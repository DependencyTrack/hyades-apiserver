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

import org.glassfish.jersey.server.spi.Container;
import org.glassfish.jersey.server.spi.ContainerLifecycleListener;

import jakarta.ws.rs.ext.Provider;

@Provider
public class InjectionManagerInitializer implements ContainerLifecycleListener {

    @Override
    public void onStartup(final Container container) {
        InjectionManagerHolder.set(container.getApplicationHandler().getInjectionManager());
    }

    @Override
    public void onReload(final Container container) {
        InjectionManagerHolder.set(container.getApplicationHandler().getInjectionManager());
    }

    @Override
    public void onShutdown(final Container container) {
        InjectionManagerHolder.unset();
    }

}
