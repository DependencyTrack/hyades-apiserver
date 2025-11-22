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
package org.dependencytrack.dex.engine.persistence;

import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.dex.engine.persistence.jdbi.PaginationConfig;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

abstract class AbstractDao {

    final Handle jdbiHandle;

    AbstractDao(final Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
    }

    <T extends PageToken> @Nullable String encodePageToken(final @Nullable T token) {
        if (token == null) {
            return null;
        }

        final PageTokenEncoder encoder = jdbiHandle
                .getConfig(PaginationConfig.class)
                .getPageTokenEncoder();

        return encoder.encode(token);
    }

    <T extends PageToken> @Nullable T decodePageToken(final @Nullable String token, final Class<T> tokenClass) {
        if (token == null) {
            return null;
        }

        final PageTokenEncoder encoder = jdbiHandle
                .getConfig(PaginationConfig.class)
                .getPageTokenEncoder();

        return encoder.decode(token, tokenClass);
    }

}
