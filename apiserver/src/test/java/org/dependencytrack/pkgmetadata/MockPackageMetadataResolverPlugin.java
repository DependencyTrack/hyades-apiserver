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
package org.dependencytrack.pkgmetadata;

import com.github.packageurl.PackageURL;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.Plugin;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

final class MockPackageMetadataResolverPlugin implements Plugin {

    private final MockPackageMetadataResolverFactory factory;

    MockPackageMetadataResolverPlugin(
            AtomicReference<Function<PackageURL, PackageMetadata>> resolveFnRef) {
        this.factory = new MockPackageMetadataResolverFactory(resolveFnRef);
    }

    @Override
    public @NonNull Collection<? extends ExtensionFactory<? extends ExtensionPoint>> extensionFactories() {
        return List.of(factory);
    }

    private static final class MockPackageMetadataResolver implements PackageMetadataResolver {

        private final AtomicReference<Function<PackageURL, PackageMetadata>> resolveFnRef;

        MockPackageMetadataResolver(AtomicReference<Function<PackageURL, PackageMetadata>> resolveFnRef) {
            this.resolveFnRef = resolveFnRef;
        }

        @Override
        public @Nullable PackageMetadata resolve(PackageURL purl, @Nullable PackageRepository repository) {
            return resolveFnRef.get().apply(purl);
        }

    }

    private static final class MockPackageMetadataResolverFactory implements PackageMetadataResolverFactory {

        private final AtomicReference<Function<PackageURL, PackageMetadata>> resolveFnRef;

        MockPackageMetadataResolverFactory(AtomicReference<Function<PackageURL, PackageMetadata>> resolveFnRef) {
            this.resolveFnRef = resolveFnRef;
        }

        @Override
        public @NonNull String extensionName() {
            return "mock";
        }

        @Override
        public @NonNull Class<? extends PackageMetadataResolver> extensionClass() {
            return MockPackageMetadataResolver.class;
        }

        @Override
        public void init(@NonNull ServiceRegistry serviceRegistry) {
        }

        @Override
        public PackageMetadataResolver create() {
            return new MockPackageMetadataResolver(resolveFnRef);
        }

        @Override
        public @Nullable PackageURL normalize(PackageURL purl) {
            if ("maven".equals(purl.getType())) {
                return purl;
            }
            return null;
        }

        @Override
        public boolean requiresRepository() {
            return false;
        }

    }

}
