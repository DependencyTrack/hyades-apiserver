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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.common.health.HealthCheckRegistry;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;
import org.eclipse.microprofile.health.Readiness;
import org.eclipse.microprofile.health.Startup;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HealthServletTest {

    private HttpServletRequest requestMock;
    private HttpServletResponse responseMock;
    private ByteArrayOutputStream responseOutputStream;

    @BeforeEach
    void beforeEach() throws Exception {
        requestMock = mock(HttpServletRequest.class);
        responseMock = mock(HttpServletResponse.class);
        responseOutputStream = new ByteArrayOutputStream();
        final var responseWriter = new PrintWriter(responseOutputStream);
        when(responseMock.getWriter()).thenReturn(responseWriter);
    }

    @Test
    void shouldReportStatusUpWhenNoChecksAreRegistered() throws Exception {
        final var servlet = new HealthServlet(new HealthCheckRegistry(Collections.emptyList()));
        servlet.init();
        servlet.doGet(requestMock, responseMock);

        verify(responseMock).setStatus(eq(200));
        verify(responseMock).setHeader(eq("Content-Type"), eq("application/json"));
        assertThatJson(responseOutputStream.toString(StandardCharsets.UTF_8))
                .isEqualTo("""
                        {
                          "status": "UP",
                          "checks": []
                        }
                        """);
    }

    @Test
    void shouldReportStatusUpWhenAllChecksAreUp() throws Exception {
        final var checkRegistry = new HealthCheckRegistry(List.of(
                new MockReadinessCheck(() -> HealthCheckResponse.up("foo")),
                new MockReadinessCheck(() -> HealthCheckResponse.up("bar"))));

        final var servlet = new HealthServlet(checkRegistry);
        servlet.init();
        servlet.doGet(requestMock, responseMock);

        verify(responseMock).setStatus(eq(200));
        verify(responseMock).setHeader(eq("Content-Type"), eq("application/json"));
        assertThatJson(responseOutputStream.toString(StandardCharsets.UTF_8))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                          "status": "UP",
                          "checks": [
                            {
                              "name": "foo",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "bar",
                              "status": "UP",
                              "data": null
                            }
                          ]
                        }
                        """);
    }

    @Test
    void shouldReportStatusDownWhenAtLeastOneCheckIsDown() throws Exception {
        final var checkRegistry = new HealthCheckRegistry(List.of(
                new MockReadinessCheck(() -> HealthCheckResponse.up("foo")),
                new MockReadinessCheck(() -> HealthCheckResponse.down("bar"))));

        final var servlet = new HealthServlet(checkRegistry);
        servlet.init();
        servlet.doGet(requestMock, responseMock);

        verify(responseMock).setStatus(eq(503));
        verify(responseMock).setHeader(eq("Content-Type"), eq("application/json"));
        assertThatJson(responseOutputStream.toString(StandardCharsets.UTF_8))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                          "status": "DOWN",
                          "checks": [
                            {
                              "name": "foo",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "bar",
                              "status": "DOWN",
                              "data": null
                            }
                          ]
                        }
                        """);
    }

    @Test
    void shouldNotReportAnythingWhenCallingAtLeastOneCheckFailed() throws Exception {
        final var checkRegistry = new HealthCheckRegistry(List.of(
                new MockReadinessCheck(() -> HealthCheckResponse.up("foo")),
                new MockReadinessCheck(() -> {
                    throw new IllegalStateException("Simulated check exception");
                })
        ));

        final var servlet = new HealthServlet(checkRegistry);
        servlet.init();
        servlet.doGet(requestMock, responseMock);

        verify(responseMock).sendError(eq(500));
        verify(responseMock, never()).setHeader(eq("Content-Type"), anyString());
        assertThat(responseOutputStream.size()).isZero();
    }

    @Test
    void shouldIncludeLivenessCheckWhenLivenessIsRequested() throws Exception {
        final var checkRegistry = new HealthCheckRegistry(List.of(
                new MockLivenessCheck(() -> HealthCheckResponse.up("live")),
                new MockReadinessCheck(() -> HealthCheckResponse.up("ready")),
                new MockStartupCheck(() -> HealthCheckResponse.up("start")),
                new MockAllTypesCheck(() -> HealthCheckResponse.up("all"))));

        when(requestMock.getPathInfo()).thenReturn("/live");

        final var servlet = new HealthServlet(checkRegistry);
        servlet.init();
        servlet.doGet(requestMock, responseMock);

        verify(responseMock).setStatus(eq(200));
        verify(responseMock).setHeader(eq("Content-Type"), eq("application/json"));
        assertThatJson(responseOutputStream.toString(StandardCharsets.UTF_8))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                          "status": "UP",
                          "checks": [
                            {
                              "name": "live",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "all",
                              "status": "UP",
                              "data": null
                            }
                          ]
                        }
                        """);
    }

    @Test
    void shouldIncludeReadinessCheckWhenReadinessIsRequested() throws Exception {
        final var checkRegistry = new HealthCheckRegistry(List.of(
                new MockLivenessCheck(() -> HealthCheckResponse.up("live")),
                new MockReadinessCheck(() -> HealthCheckResponse.up("ready")),
                new MockStartupCheck(() -> HealthCheckResponse.up("start")),
                new MockAllTypesCheck(() -> HealthCheckResponse.up("all"))));

        when(requestMock.getPathInfo()).thenReturn("/ready");

        final var servlet = new HealthServlet(checkRegistry);
        servlet.init();
        servlet.doGet(requestMock, responseMock);

        verify(responseMock).setStatus(eq(200));
        verify(responseMock).setHeader(eq("Content-Type"), eq("application/json"));
        assertThatJson(responseOutputStream.toString(StandardCharsets.UTF_8))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                          "status": "UP",
                          "checks": [
                            {
                              "name": "ready",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "all",
                              "status": "UP",
                              "data": null
                            }
                          ]
                        }
                        """);
    }

    @Test
    void shouldIncludeStartupCheckWhenStartupIsRequested() throws Exception {
        final var checkRegistry = new HealthCheckRegistry(List.of(
                new MockLivenessCheck(() -> HealthCheckResponse.up("live")),
                new MockReadinessCheck(() -> HealthCheckResponse.up("ready")),
                new MockStartupCheck(() -> HealthCheckResponse.up("start")),
                new MockAllTypesCheck(() -> HealthCheckResponse.up("all"))));

        when(requestMock.getPathInfo()).thenReturn("/started");

        final var servlet = new HealthServlet(checkRegistry);
        servlet.init();
        servlet.doGet(requestMock, responseMock);

        verify(responseMock).setStatus(eq(200));
        verify(responseMock).setHeader(eq("Content-Type"), eq("application/json"));
        assertThatJson(responseOutputStream.toString(StandardCharsets.UTF_8))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                          "status": "UP",
                          "checks": [
                            {
                              "name": "start",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "all",
                              "status": "UP",
                              "data": null
                            }
                          ]
                        }
                        """);
    }

    @Test
    void shouldIncludeAllChecksWhenAllAreRequested() throws Exception {
        final var checkRegistry = new HealthCheckRegistry(List.of(
                new MockLivenessCheck(() -> HealthCheckResponse.up("live")),
                new MockReadinessCheck(() -> HealthCheckResponse.up("ready")),
                new MockStartupCheck(() -> HealthCheckResponse.up("start")),
                new MockAllTypesCheck(() -> HealthCheckResponse.up("all"))));

        when(requestMock.getPathInfo()).thenReturn("/");

        final var servlet = new HealthServlet(checkRegistry);
        servlet.init();
        servlet.doGet(requestMock, responseMock);

        verify(responseMock).setStatus(eq(200));
        verify(responseMock).setHeader(eq("Content-Type"), eq("application/json"));
        assertThatJson(responseOutputStream.toString(StandardCharsets.UTF_8))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                          "status": "UP",
                          "checks": [
                            {
                              "name": "live",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "ready",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "start",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "all",
                              "status": "UP",
                              "data": null
                            }
                          ]
                        }
                        """);
    }

    private abstract static class AbstractMockCheck implements HealthCheck {
        private final Supplier<HealthCheckResponse> responseSupplier;

        private AbstractMockCheck(final Supplier<HealthCheckResponse> responseSupplier) {
            this.responseSupplier = responseSupplier;
        }

        @Override
        public HealthCheckResponse call() {
            return responseSupplier.get();
        }
    }

    @Liveness
    private static class MockLivenessCheck extends AbstractMockCheck {
        private MockLivenessCheck(final Supplier<HealthCheckResponse> responseSupplier) {
            super(responseSupplier);
        }
    }

    @Readiness
    private static class MockReadinessCheck extends AbstractMockCheck {
        private MockReadinessCheck(final Supplier<HealthCheckResponse> responseSupplier) {
            super(responseSupplier);
        }
    }

    @Startup
    private static class MockStartupCheck extends AbstractMockCheck {
        private MockStartupCheck(final Supplier<HealthCheckResponse> responseSupplier) {
            super(responseSupplier);
        }
    }

    @Liveness
    @Readiness
    @Startup
    private static class MockAllTypesCheck extends AbstractMockCheck {
        private MockAllTypesCheck(final Supplier<HealthCheckResponse> responseSupplier) {
            super(responseSupplier);
        }
    }

}