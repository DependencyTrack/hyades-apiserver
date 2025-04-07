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
