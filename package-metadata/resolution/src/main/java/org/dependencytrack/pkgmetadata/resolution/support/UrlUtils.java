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
package org.dependencytrack.pkgmetadata.resolution.support;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;

public final class UrlUtils {

    private static final Pattern LEADING_TRAILING_SLASHES = Pattern.compile("^/+|/+$");

    private UrlUtils() {
    }

    public static String join(String base, String... segments) {
        final var sb = new StringBuilder();
        sb.append(trimTrailingSlash(base));
        for (final String segment : segments) {
            sb.append('/').append(encodePathSegment(trimLeadingAndTrailingSlashes(segment)));
        }
        return sb.toString();
    }

    public static String trimTrailingSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private static String trimLeadingAndTrailingSlashes(String value) {
        return LEADING_TRAILING_SLASHES.matcher(value).replaceAll("");
    }

    private static String encodePathSegment(String segment) {
        try {
            // The multi-arg URI constructor percent-encodes the path per RFC 3986.
            // It treats '/' as a path separator, so we encode it separately since
            // this method encodes a single segment where '/' is a literal character.
            return new URI(null, null, "/" + segment, null)
                    .getRawPath()
                    .substring(1)
                    .replace("/", "%2F");
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid path segment: " + segment, e);
        }
    }

}
