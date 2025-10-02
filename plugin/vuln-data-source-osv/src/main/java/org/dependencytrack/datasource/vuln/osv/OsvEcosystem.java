package org.dependencytrack.datasource.vuln.osv;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public enum OsvEcosystem {

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

