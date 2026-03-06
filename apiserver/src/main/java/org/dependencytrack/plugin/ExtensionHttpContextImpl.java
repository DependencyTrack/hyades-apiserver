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
package org.dependencytrack.plugin;

import org.dependencytrack.plugin.api.ExtensionHttpContext;

import java.net.ProxySelector;
import java.net.http.HttpClient;

final class ExtensionHttpContextImpl implements ExtensionHttpContext {

    private final org.dependencytrack.common.HttpClient httpClient;

    ExtensionHttpContextImpl(org.dependencytrack.common.HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public HttpClient client() {
        return httpClient;
    }

    @Override
    public String userAgent() {
        return httpClient.userAgent();
    }

    @Override
    public ProxySelector proxySelector() {
        return httpClient.proxy().orElse(ProxySelector.getDefault());
    }

}
