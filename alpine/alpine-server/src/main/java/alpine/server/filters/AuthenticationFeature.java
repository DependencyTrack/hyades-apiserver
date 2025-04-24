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
package alpine.server.filters;

import alpine.Config;
import alpine.server.auth.AuthenticationNotRequired;

import jakarta.ws.rs.container.DynamicFeature;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.FeatureContext;
import jakarta.ws.rs.ext.Provider;
import java.lang.reflect.Method;

/**
 * Determines if authentication is required or not (via {@link Config.AlpineKey#ENFORCE_AUTHENTICATION}
 * and if so mandates that all resources requested are authenticated unless they are annotated
 * with {@link AuthenticationNotRequired}.
 *
 * @see AuthenticationFilter
 * @author Steve Springett
 * @since 1.0.0
 */
@Provider
public class AuthenticationFeature implements DynamicFeature {

    private static final boolean ENFORCE_AUTHENTICATION = Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.ENFORCE_AUTHENTICATION);

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        if (ENFORCE_AUTHENTICATION) {
            final Method method = resourceInfo.getResourceMethod();
            if (!method.isAnnotationPresent(AuthenticationNotRequired.class)) {
                context.register(AuthenticationFilter.class);
            }
        }
    }

}
