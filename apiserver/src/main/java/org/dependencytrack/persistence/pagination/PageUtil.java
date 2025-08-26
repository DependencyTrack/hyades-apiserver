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
package org.dependencytrack.persistence.pagination;

import alpine.security.crypto.DataEncryption;
import org.dependencytrack.api.v2.model.PaginationLinks;
import org.dependencytrack.api.v2.model.PaginationMetadata;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper;

import jakarta.ws.rs.core.UriInfo;
import java.util.Base64;

/**
 * @since 5.6.0
 */
public final class PageUtil {

    private PageUtil() {
    }

    public static String decodePageToken(final String encodedToken) {
        if (encodedToken == null) {
            return null;
        }

        try {
            final byte[] encryptedTokenBytes = Base64.getUrlDecoder().decode(encodedToken);
            final byte[] decryptedToken = DataEncryption.decryptAsBytes(encryptedTokenBytes);
            return new String(decryptedToken);
        } catch (Exception e) {
            throw new InvalidPageTokenException(e);
        }
    }

    public static <T> T decodePageToken(final Handle handle, final String encodedToken, final Class<T> tokenClass) {
        final String decodedToken = decodePageToken(encodedToken);
        if (decodedToken == null) {
            return null;
        }

        final JsonMapper.TypedJsonMapper jsonMapper = handle
                .getConfig(JsonConfig.class)
                .getJsonMapper()
                .forType(tokenClass, handle.getConfig());

        try {
            return (T) jsonMapper.fromJson(decodedToken, handle.getConfig());
        } catch (RuntimeException e) {
            throw new InvalidPageTokenException(e);
        }
    }

    public static String encodePageToken(final String pageToken) {
        if (pageToken == null) {
            return null;
        }

        try {
            final byte[] encryptedTokenBytes = DataEncryption.encryptAsBytes(pageToken);
            return Base64.getUrlEncoder().encodeToString(encryptedTokenBytes);
        } catch (Exception e) {
            throw new InvalidPageTokenException(e);
        }
    }

    public static <T> String encodePageToken(final Handle handle, final T pageToken) {
        if (pageToken == null) {
            return null;
        }

        final JsonMapper.TypedJsonMapper jsonMapper = handle
                .getConfig(JsonConfig.class)
                .getJsonMapper()
                .forType(Object.class, handle.getConfig());

        final String tokenJson;
        try {
            tokenJson = jsonMapper.toJson(pageToken, handle.getConfig());
        } catch (RuntimeException e) {
            throw new InvalidPageTokenException(e);
        }

        return encodePageToken(tokenJson);
    }

    public static PaginationMetadata createPaginationMetadata(final UriInfo uriInfo, final Page<?> page) {
        return PaginationMetadata.builder()
                .links(PaginationLinks.builder()
                        .self(uriInfo.getRequestUri())
                        .next(page.nextPageToken() != null ?
                                uriInfo.getRequestUriBuilder()
                                        .replaceQueryParam("page_token", page.nextPageToken())
                                        .build()
                                : null)
                        .build())
                .build();
    }
}
