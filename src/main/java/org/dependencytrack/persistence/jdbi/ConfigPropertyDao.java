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
package org.dependencytrack.persistence.jdbi;

import alpine.model.IConfigProperty;
import alpine.security.crypto.DataEncryption;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.jdbi.v3.sqlobject.customizer.BindBean;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.NoSuchElementException;
import java.util.Optional;

/**
 * @since 5.6.0
 */
public interface ConfigPropertyDao {

    @SqlQuery("""
            SELECT "PROPERTYVALUE"
              FROM "CONFIGPROPERTY"
             WHERE "GROUPNAME" = :groupName
               AND "PROPERTYNAME" = :propertyName
            """)
    Optional<String> getOptionalRawValue(@BindBean ConfigPropertyConstants property);

    default Optional<String> getOptionalValue(final ConfigPropertyConstants property) {
        final Optional<String> optionalRawValue = getOptionalRawValue(property);
        if (optionalRawValue.isEmpty() || property.getPropertyType() != IConfigProperty.PropertyType.ENCRYPTEDSTRING) {
            return optionalRawValue;
        }

        try {
            final String decryptedValue = DataEncryption.decryptAsString(optionalRawValue.get());
            return Optional.of(decryptedValue);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt value", e);
        }
    }

    default <T> Optional<T> getOptionalValue(final ConfigPropertyConstants property, final Class<T> clazz) {
        final Optional<String> optionalStringValue = getOptionalValue(property);
        if (optionalStringValue.isEmpty()) {
            return Optional.empty();
        }

        final T convertedValue;

        // Add more conversions as needed.
        if (clazz.isAssignableFrom(CharSequence.class)) {
            convertedValue = clazz.cast(optionalStringValue.get());
        } else if (clazz.isAssignableFrom(String.class)) {
            convertedValue = clazz.cast(optionalStringValue.get());
        } else if (clazz.isAssignableFrom(Boolean.class)) {
            convertedValue = clazz.cast(Boolean.parseBoolean(optionalStringValue.get()));
        } else if (clazz.isAssignableFrom(Integer.class)) {
            convertedValue = clazz.cast(Integer.parseInt(optionalStringValue.get()));
        } else {
            throw new IllegalArgumentException("Cannot convert to %s".formatted(clazz.getName()));
        }

        return Optional.of(convertedValue);
    }

    default <T> T getValue(final ConfigPropertyConstants property, final Class<T> clazz) {
        return getOptionalValue(property, clazz).orElseThrow(NoSuchElementException::new);
    }

}
