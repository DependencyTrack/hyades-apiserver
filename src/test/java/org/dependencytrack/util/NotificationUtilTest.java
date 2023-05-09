package org.dependencytrack.util;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.junit.Assert;
import org.junit.Test;

public class NotificationUtilTest extends PersistenceCapableTest {

    @Test
    public void testCleanNotificationPublishers() {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        generator.contextInitialized(null);
        Assert.assertEquals(DefaultNotificationPublishers.values().length, qm.getAllNotificationPublishers().size());
        NotificationUtil.cleanExistingNotificationPublishers(qm);
        Assert.assertEquals(0, qm.getAllNotificationPublishers().size());
    }
}
