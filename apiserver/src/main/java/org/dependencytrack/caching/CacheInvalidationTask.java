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
package org.dependencytrack.caching;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.caching.api.Cache;
import org.dependencytrack.caching.api.CacheProvider;

import java.util.Collection;

/**
 * @since 5.7.0
 */
public final class CacheInvalidationTask implements Subscriber {

    private final CacheProvider cacheProvider;

    public CacheInvalidationTask(CacheProvider cacheProvider) {
        this.cacheProvider = cacheProvider;
    }

    @Override
    public void inform(Event event) {
        if (event instanceof CacheInvalidationEvent(String cacheName, Collection<String> keys)) {
            final Cache<?> cache = cacheProvider.getCache(cacheName);
            if (cache != null) {
                cache.invalidate(keys);
            }
        }
    }

}
