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
package org.dependencytrack.plugin.api;

import java.net.ProxySelector;
import java.net.http.HttpClient;

/**
 * @since 5.7.0
 */
public interface ExtensionHttpContext {

    HttpClient client();

    String userAgent();

    ProxySelector proxySelector();

    static ExtensionHttpContext ofDefault() {
        return Default.INSTANCE;
    }

    final class Default implements ExtensionHttpContext {

        private static final Default INSTANCE = new Default();
        private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();

        private Default() {
        }

        @Override
        public HttpClient client() {
            return HTTP_CLIENT;
        }

        @Override
        public String userAgent() {
            return "Dependency-Track";
        }

        @Override
        public ProxySelector proxySelector() {
            return ProxySelector.getDefault();
        }

    }

}
