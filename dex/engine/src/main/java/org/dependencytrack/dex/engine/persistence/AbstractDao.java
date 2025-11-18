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

import org.dependencytrack.dex.engine.api.pagination.InvalidPageTokenException;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.result.UnableToProduceResultException;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper.TypedJsonMapper;
import org.jspecify.annotations.Nullable;

import java.util.Base64;

abstract class AbstractDao {

    final Handle jdbiHandle;

    AbstractDao(final Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
    }

    <T> @Nullable String encodePageToken(final @Nullable T token) {
        if (token == null) {
            return null;
        }

        final TypedJsonMapper jsonMapper = jdbiHandle
                .getConfig(JsonConfig.class)
                .getJsonMapper()
                .forType(token.getClass(), jdbiHandle.getConfig());

        final String pageTokenJson = jsonMapper.toJson(token, jdbiHandle.getConfig());
        return Base64.getUrlEncoder().encodeToString(pageTokenJson.getBytes());
    }

    @SuppressWarnings("unchecked")
    <T> @Nullable T decodePageToken(final @Nullable String token, final Class<T> tokenClass) {
        if (token == null || token.isBlank()) {
            return null;
        }

        final TypedJsonMapper jsonMapper = jdbiHandle
                .getConfig(JsonConfig.class)
                .getJsonMapper()
                .forType(tokenClass, jdbiHandle.getConfig());

        try {
            final byte[] tokenBytes = Base64.getUrlDecoder().decode(token);
            return (T) jsonMapper.fromJson(new String(tokenBytes), jdbiHandle.getConfig());
        } catch (IllegalArgumentException | UnableToProduceResultException e) {
            throw new InvalidPageTokenException(e);
        }
    }

}
