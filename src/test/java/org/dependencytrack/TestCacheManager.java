package org.dependencytrack;

import alpine.server.cache.AbstractCacheManager;

import java.util.concurrent.TimeUnit;

public class TestCacheManager extends AbstractCacheManager {

    public TestCacheManager(final long expiresAfter, final TimeUnit timeUnit, final long maxSize) {
        super(expiresAfter, timeUnit, maxSize);
    }

}
