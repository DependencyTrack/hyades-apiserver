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
package org.dependencytrack.plugin.runtime;

import org.dependencytrack.plugin.api.ExtensionHttpContext;

import java.net.ProxySelector;
import java.net.http.HttpClient;

final class ExtensionHttpContextImpl implements ExtensionHttpContext {

    private final HttpClient client;
    private final String userAgent;
    private final ProxySelector proxySelector;

    ExtensionHttpContextImpl(HttpClient client, String userAgent, ProxySelector proxySelector) {
        this.client = client;
        this.userAgent = userAgent;
        this.proxySelector = proxySelector;
    }

    @Override
    public HttpClient client() {
        return client;
    }

    @Override
    public String userAgent() {
        return userAgent;
    }

    @Override
    public ProxySelector proxySelector() {
        return proxySelector;
    }

}
