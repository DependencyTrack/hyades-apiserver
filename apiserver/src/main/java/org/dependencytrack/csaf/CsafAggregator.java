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
package org.dependencytrack.csaf;

import com.fasterxml.uuid.Generators;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
public class CsafAggregator {

    private final UUID id;
    private final URI url;
    private final URI namespace;
    private final String name;
    private boolean enabled;
    private @Nullable Instant lastDiscoveryAt;
    private Instant createdAt;
    private @Nullable Instant updatedAt;

    CsafAggregator(UUID id, URI url, URI namespace, String name) {
        this.id = requireNonNull(id, "id must not be null");
        this.namespace = requireNonNull(namespace, "namespace must not be null");
        this.name = requireNonNull(name, "name must not be null");
        this.url = requireNonNull(url, "url must not be null");
        this.createdAt = Instant.now();
    }

    public CsafAggregator(URI url, URI namespace, String name) {
        this(Generators.timeBasedEpochRandomGenerator().generate(), url, namespace, name);
    }

    public UUID getId() {
        return id;
    }

    public URI getNamespace() {
        return namespace;
    }

    public String getName() {
        return name;
    }

    public URI getUrl() {
        return url;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public @Nullable Instant getLastDiscoveryAt() {
        return lastDiscoveryAt;
    }

    public void setLastDiscoveryAt(@Nullable Instant lastDiscoveryAt) {
        this.lastDiscoveryAt = lastDiscoveryAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = requireNonNull(createdAt, "createdAt must not be null");
    }

    public @Nullable Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(@Nullable Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof CsafAggregator that)) {
            return false;
        }

        return Objects.equals(url, that.url);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(url);
    }

}
