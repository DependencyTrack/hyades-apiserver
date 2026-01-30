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
package org.dependencytrack.event;

import alpine.event.framework.EventService;
import alpine.event.framework.SingleThreadedEventService;
import alpine.event.framework.Subscriber;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import org.dependencytrack.plugin.PluginManager;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class EventSubsystemInitializerTest {

    @Test
    void shouldSubscribeAndUnsubscribeListeners() throws Exception {
        // Test against "production" config for more realistic test coverage.
        final Config config = ConfigProvider.getConfig();

        final var eventServiceMock = mock(EventService.class);
        final var singleThreadedEventServiceMock = mock(SingleThreadedEventService.class);
        final var pluginManager = new PluginManager(
                config,
                secretName -> null,
                Collections.emptyList());
        final var servletContextMock = mock(ServletContext.class);

        doReturn(pluginManager)
                .when(servletContextMock).getAttribute(eq(PluginManager.class.getName()));

        final var initializer = new EventSubsystemInitializer(
                config,
                eventServiceMock,
                singleThreadedEventServiceMock);
        initializer.contextInitialized(new ServletContextEvent(servletContextMock));

        final var subscriberCaptor = ArgumentCaptor.forClass(Subscriber.class);
        verify(eventServiceMock, atLeastOnce()).subscribe(any(Class.class), subscriberCaptor.capture());

        final var singleThreadedSubscriberCaptor = ArgumentCaptor.forClass(Subscriber.class);
        verify(singleThreadedEventServiceMock, atLeastOnce()).subscribe(any(Class.class), singleThreadedSubscriberCaptor.capture());

        initializer.contextDestroyed(new ServletContextEvent(servletContextMock));

        for (final Subscriber subscriber : subscriberCaptor.getAllValues()) {
            verify(eventServiceMock).unsubscribe(eq(subscriber.getClass()));
        }
        for (final Subscriber subscriber : singleThreadedSubscriberCaptor.getAllValues()) {
            verify(singleThreadedEventServiceMock).unsubscribe(eq(subscriber.getClass()));
        }

        verify(eventServiceMock).shutdown(any(Duration.class));
        verify(singleThreadedEventServiceMock).shutdown(any(Duration.class));
    }

}