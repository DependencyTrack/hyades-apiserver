package org.dependencytrack.tasks;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.server.tasks.LdapSyncTask;
import alpine.event.LdapSyncEvent;
import org.dependencytrack.util.LockProvider;

import static org.dependencytrack.tasks.LockName.LDAP_SYNC_TASK_LOCK;

public class LdapSyncTaskWrapper implements Subscriber {

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
            LockProvider.executeWithLock(LDAP_SYNC_TASK_LOCK, (Runnable) () -> this.ldapSyncTask.inform(new LdapSyncEvent()));
        }
    }
}

