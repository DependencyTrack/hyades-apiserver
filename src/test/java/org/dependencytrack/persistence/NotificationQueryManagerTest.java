package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.junit.Assert;
import org.junit.Test;

public class NotificationQueryManagerTest extends PersistenceCapableTest {

    @Test
    public void testGetNotificationPublisher() {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        generator.contextInitialized(null);
        var publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        Assert.assertEquals("SlackPublisher", publisher.getPublisherClass());
    }

    @Test
    public void testGetDefaultNotificationPublisher() {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        generator.contextInitialized(null);
        var publisher = qm.getDefaultNotificationPublisherByName(DefaultNotificationPublishers.SLACK.getPublisherName());
        Assert.assertEquals("Slack", publisher.getName());
        Assert.assertEquals("SlackPublisher", publisher.getPublisherClass());

        publisher.setPublisherClass("UpdatedClassName");
        qm.updateNotificationPublisher(publisher);
        publisher = qm.getDefaultNotificationPublisherByName(DefaultNotificationPublishers.SLACK.getPublisherName());
        Assert.assertEquals("Slack", publisher.getName());
        Assert.assertEquals("UpdatedClassName", publisher.getPublisherClass());
    }
}
