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
package org.dependencytrack.event.kafka.processor;

import io.smallrye.config.SmallRyeConfigBuilder;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class ProcessorInitializerTest {

    @Test
    void shouldNotInitializeProcessorsWhenDisabled() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.kafka.processor.enabled", "false")
                .build();

        final var servletContextMock = mock(ServletContext.class);

        final var initializer = new ProcessorInitializer(config);
        initializer.contextInitialized(new ServletContextEvent(servletContextMock));

        verify(servletContextMock, never()).getAttribute(any());
    }

}
