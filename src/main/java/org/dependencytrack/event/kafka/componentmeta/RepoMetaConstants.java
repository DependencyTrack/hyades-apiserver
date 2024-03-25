package org.dependencytrack.event.kafka.componentmeta;

import java.util.List;

public class RepoMetaConstants {

    public static final long TIME_SPAN = 60 * 60 * 1000L;
    public static final List<String> SUPPORTED_PACKAGE_URLS_FOR_INTEGRITY_CHECK =List.of("maven", "npm", "pypi");
}