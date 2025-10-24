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
package org.dependencytrack.model.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.net.URI;

/**
 * A basic domain validator.
 *
 * @since 5.7.0
 */
public class ValidDomainValidator implements ConstraintValidator<ValidUuid, String> {

    @Override
    public boolean isValid(final String domainString, final ConstraintValidatorContext validatorContext) {
        if (domainString == null) {
            // null-ness is expected to be validated using @NotNull
            return true;
        }

        // A very very very simple approach to validate a domain. We try to create a URI with the domain
        // and check if the host matches the input string and it must contain one "." character.
        try {
            if (!domainString.contains(".")) {
                return false;
            }

            URI uri = URI.create("https://" + domainString);
            String host = uri.getHost();
            return host != null && host.equals(domainString);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}