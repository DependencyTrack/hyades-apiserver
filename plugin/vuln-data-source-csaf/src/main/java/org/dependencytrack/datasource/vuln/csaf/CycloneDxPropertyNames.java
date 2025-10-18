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
package org.dependencytrack.datasource.vuln.csaf;

import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Property;

import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * A utility class for CycloneDX property names used to store security advisory-related metadata.
 *
 * @since 5.7.0
 */
public final class CycloneDxPropertyNames {

    public static final String PROPERTY_ADVISORY_TITLE = "internal:advisory:title";
    public static final String PROPERTY_ADVISORY_PROVIDER_ID = "internal:advisory:provider:id";
    public static final String PROPERTY_ADVISORY_JSON = "internal:advisory:json";
    public static final String PROPERTY_ADVISORY_PUBLISHER_NAMESPACE = "internal:advisory:publisher:namespace";
    public static final String PROPERTY_ADVISORY_NAME = "internal:advisory:name";
    public static final String PROPERTY_ADVISORY_VERSION = "internal:advisory:version";
    public static final String PROPERTY_ADVISORY_UPDATED = "internal:advisory:updated";
    public static final String PROPERTY_ADVISORY_URL = "internal:advisory:url";
    public static final String PROPERTY_ADVISORY_FORMAT = "internal:advisory:format";

    private CycloneDxPropertyNames() {
    }

    /**
     * Extracts a property of a given type from the given BOV's properties.
     *
     * @param bov the BOV to extract the property from
     * @param propertyName the name of the property to extract
     * @param type the type of the property to extract
     * @return the property value, or null if not found or if the type is unsupported
     * @param <T> the type of the property to extract
     */
    public static <T> T extractProperty(final Bom bov, final String propertyName, final Class<T> type) {
        for (final Property property : bov.getPropertiesList()) {
            if (propertyName.equals(property.getName())) {
                if (type.equals(String.class)) {
                    return type.cast(property.getValue());
                } else if (type.equals(Integer.class)) {
                    return type.cast(Integer.parseInt(property.getValue()));
                } else if (type.equals(Instant.class)) {
                    try {
                        return type.cast(Instant.parse(property.getValue()));
                    } catch (DateTimeParseException e) {
                        return null;
                    }
                }
            }
        }

        return null;
    }

}
