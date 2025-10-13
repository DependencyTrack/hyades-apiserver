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
package org.dependencytrack.datasource.vuln.osv;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The ecosystems are defined at https://ossf.github.io/osv-schema/#defined-ecosystems
 * Update this enum if the source definition changes.
 */
enum OsvEcosystem {

    ALMALINUX("AlmaLinux"),
    ALPAQUITA("Alpaquita"),
    ALPINE("Alpine"),
    ANDROID("Android"),
    BELLSOFT_HARDENED_CONTAINERS("BellSoft Hardened Containers"),
    BIOCONDUCTOR("Bioconductor"),
    BITNAMI("Bitnami"),
    CHAINGUARD("Chainguard"),
    CONANCENTER("ConanCenter"),
    CRAN("CRAN"),
    CRATES_IO("crates.io"),
    DEBIAN("Debian"),
    ECHO("Echo"),
    GHC("GHC"),
    GITHUB_ACTIONS("GitHub Actions"),
    GO("Go"),
    HACKAGE("Hackage"),
    HEX("Hex"),
    KUBERNETES("Kubernetes"),
    LINUX("Linux"),
    MAGEIA("Mageia"),
    MAVEN("Maven"),
    MINIMOS("MinimOS"),
    NPM("npm"),
    NUGET("NuGet"),
    OPENEULER("openEuler"),
    OPENSUSE("openSUSE"),
    OSS_FUZZ("OSS-Fuzz"),
    PACKAGIST("Packagist"),
    PHOTON_OS("Photon OS"),
    PUB("Pub"),
    PYPI("PyPI"),
    RED_HAT("Red Hat"),
    ROCKY_LINUX("Rocky Linux"),
    RUBYGEMS("RubyGems"),
    SUSE("SUSE"),
    SWIFTURL("SwiftURL"),
    UBUNTU("Ubuntu"),
    WOLFI("Wolfi");

    private final String name;

    OsvEcosystem(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public static Set<String> getOsvEcosystems() {
        return Arrays.stream(OsvEcosystem.values())
                .map(OsvEcosystem::getName)
                .collect(Collectors.toSet());
    }
}

