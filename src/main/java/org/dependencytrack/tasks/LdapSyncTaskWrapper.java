package org.dependencytrack.tasks;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.server.tasks.LdapSyncTask;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import net.javacrumbs.shedlock.provider.jdbc.JdbcLockProvider;
import org.dependencytrack.event.LdapSyncEvent;

import java.time.Duration;
import java.time.Instant;

import static org.dependencytrack.common.ConfigKey.TASK_LDAP_SYNC_LOCK_AT_LEAST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_LDAP_SYNC_LOCK_AT_MOST_FOR;
import static org.dependencytrack.tasks.LockName.LDAP_SYNC_TASK_LOCK;
import static org.dependencytrack.util.LockProvider.getJdbcLockProviderInstance;
import static org.dependencytrack.util.LockProvider.getLockingTaskExecutorInstance;

public class LdapSyncTaskWrapper implements Subscriber {
    private static final Logger LOGGER = Logger.getLogger(LdapSyncTaskWrapper.class);
    private final LdapSyncTask ldapSyncTask;

    public LdapSyncTaskWrapper() {
        this(new LdapSyncTask());
    }

    LdapSyncTaskWrapper(LdapSyncTask ldapSyncTask) {
        this.ldapSyncTask = ldapSyncTask;
    }

    @Override
    public void inform(Event e) {
        if (e instanceof LdapSyncEvent) {
            JdbcLockProvider instance = getJdbcLockProviderInstance();
            LockingTaskExecutor executor = getLockingTaskExecutorInstance(instance);
            LockConfiguration lockConfiguration = new LockConfiguration(Instant.now(),
                    LDAP_SYNC_TASK_LOCK.name(),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_LDAP_SYNC_LOCK_AT_MOST_FOR)),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_LDAP_SYNC_LOCK_AT_LEAST_FOR)));

            executor.executeWithLock((Runnable) () -> {
                try {
                    this.ldapSyncTask.inform(new alpine.event.LdapSyncEvent());
                } catch (Exception ex) {
                    throw new RuntimeException("Error in acquiring lock and ldap sync task", ex);
                }
            }, lockConfiguration);
        }
    }
}

