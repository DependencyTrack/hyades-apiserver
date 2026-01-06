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
package org.dependencytrack.observability;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.prometheus.client.exporter.common.TextFormat;
import io.smallrye.config.SmallRyeConfigBuilder;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.HttpHeaders;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class MetricsServletTest {

    private PrometheusMeterRegistry meterRegistry;
    private HttpServletRequest requestMock;
    private HttpServletResponse responseMock;
    private ServletOutputStream responseOutputStreamMock;

    @BeforeEach
    void beforeEach() {
        meterRegistry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        requestMock = mock(HttpServletRequest.class);
        responseMock = mock(HttpServletResponse.class);
        responseOutputStreamMock = mock(ServletOutputStream.class);

        Gauge.builder("alpine.foo.bar", () -> 666).register(meterRegistry);
    }

    @Test
    void shouldRespondWithMetricsWhenEnabled() throws Exception {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("alpine.metrics.enabled", "true")
                .build();

        when(responseMock.getOutputStream()).thenReturn(responseOutputStreamMock);

        final var servlet = new MetricsServlet(config, meterRegistry);
        servlet.init();
        servlet.doGet(requestMock, responseMock);

        verify(responseMock).setStatus(eq(HttpServletResponse.SC_OK));
        verify(responseMock).setHeader(eq(HttpHeaders.CONTENT_TYPE), eq(TextFormat.CONTENT_TYPE_004));

        final var responseBodyCaptor = ArgumentCaptor.forClass(byte[].class);
        verify(responseOutputStreamMock).write(responseBodyCaptor.capture(), anyInt(), anyInt());

        assertThat(responseBodyCaptor.getValue()).asString().startsWith("""
                # HELP alpine_foo_bar \s
                # TYPE alpine_foo_bar gauge
                alpine_foo_bar 666.0""");
    }

    @Test
    void shouldRespondWithNotFoundWhenNotEnabled() throws Exception {
        when(responseMock.getOutputStream()).thenReturn(responseOutputStreamMock);

        final var servlet = new MetricsServlet(new SmallRyeConfigBuilder().build(), meterRegistry);
        servlet.init();
        servlet.doGet(requestMock, responseMock);

        verify(responseMock).setStatus(eq(HttpServletResponse.SC_NOT_FOUND));
        verify(responseOutputStreamMock, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    @Test
    void shouldRespondWithMetricsWhenEnabledAndAuthenticated() throws Exception {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("alpine.metrics.enabled", "true")
                .withDefaultValue("alpine.metrics.auth.username", "metrics-user")
                .withDefaultValue("alpine.metrics.auth.password", "metrics-password")
                .build();

        when(requestMock.getHeader(eq(HttpHeaders.AUTHORIZATION))).thenReturn("Basic bWV0cmljcy11c2VyOm1ldHJpY3MtcGFzc3dvcmQ");

        when(responseMock.getOutputStream()).thenReturn(responseOutputStreamMock);

        final var servlet = new MetricsServlet(config, meterRegistry);
        servlet.init();
        servlet.doGet(requestMock, responseMock);

        verify(responseMock).setStatus(eq(HttpServletResponse.SC_OK));
        verify(responseMock).setHeader(eq(HttpHeaders.CONTENT_TYPE), eq(TextFormat.CONTENT_TYPE_004));

        final var responseBodyCaptor = ArgumentCaptor.forClass(byte[].class);
        verify(responseOutputStreamMock).write(responseBodyCaptor.capture(), anyInt(), anyInt());

        assertThat(responseBodyCaptor.getValue()).asString().startsWith("""
                # HELP alpine_foo_bar \s
                # TYPE alpine_foo_bar gauge
                alpine_foo_bar 666.0""");
    }

    @Test
    void shouldRespondWithUnauthorizedWhenEnabledAndAuthenticationFailed() throws Exception {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("alpine.metrics.enabled", "true")
                .withDefaultValue("alpine.metrics.auth.username", "metrics-user")
                .withDefaultValue("alpine.metrics.auth.password", "metrics-password")
                .build();

        when(requestMock.getHeader(eq(HttpHeaders.AUTHORIZATION))).thenReturn("Basic Zm9vOmJhcg");

        when(responseMock.getOutputStream()).thenReturn(responseOutputStreamMock);

        final var servlet = new MetricsServlet(config, meterRegistry);
        servlet.init();
        servlet.doGet(requestMock, responseMock);

        verify(responseMock).setStatus(eq(HttpServletResponse.SC_UNAUTHORIZED));
        verify(responseOutputStreamMock, never()).write(any(byte[].class), anyInt(), anyInt());
    }

}