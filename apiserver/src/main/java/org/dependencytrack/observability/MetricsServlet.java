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

import alpine.common.logging.Logger;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.prometheus.client.exporter.common.TextFormat;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.HttpHeaders;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.Nullable;
import org.owasp.security.logging.SecurityMarkers;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

/**
 * @since 5.7.0
 */
public final class MetricsServlet extends HttpServlet {

    private static final Logger LOGGER = Logger.getLogger(MetricsServlet.class);

    private final Config config;
    private @Nullable PrometheusMeterRegistry meterRegistry;
    private boolean metricsEnabled;
    private @Nullable String basicAuthUsername;
    private @Nullable String basicAuthPassword;

    @SuppressWarnings("unused")
    public MetricsServlet() {
        this(ConfigProvider.getConfig(), null);
    }

    MetricsServlet(Config config, @Nullable PrometheusMeterRegistry meterRegistry) {
        this.config = config;
        this.meterRegistry = meterRegistry;
    }

    @Override
    public void init() throws ServletException {
        metricsEnabled = config.getOptionalValue("dt.metrics.enabled", boolean.class)
                .or(() -> config.getOptionalValue("alpine.metrics.enabled", boolean.class))
                .orElse(false);
        basicAuthUsername = config.getOptionalValue("dt.metrics.auth.username", String.class)
                .or(() -> config.getOptionalValue("alpine.metrics.auth.username", String.class))
                .orElse(null);
        basicAuthPassword = config.getOptionalValue("dt.metrics.auth.password", String.class)
                .or(() -> config.getOptionalValue("alpine.metrics.auth.password", String.class))
                .orElse(null);

        if (metricsEnabled && meterRegistry == null) {
            meterRegistry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
            io.micrometer.core.instrument.Metrics.addRegistry(meterRegistry);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (isAuthenticationEnabled() && !isAuthenticated(req)) {
            LOGGER.warn(SecurityMarkers.SECURITY_AUDIT, "Unauthorized access attempt (IP address: " +
                    req.getRemoteAddr() + " / User-Agent: " + req.getHeader("User-Agent") + ")");
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resp.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"metrics\"");
            return;
        }

        if (metricsEnabled) {
            resp.setStatus(HttpServletResponse.SC_OK);
            resp.setHeader(HttpHeaders.CONTENT_TYPE, TextFormat.CONTENT_TYPE_004);
            meterRegistry.scrape(resp.getOutputStream());
        } else {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
        }
    }

    private boolean isAuthenticationEnabled() {
        return StringUtils.isNotBlank(basicAuthUsername) && StringUtils.isNotBlank(basicAuthPassword);
    }

    private boolean isAuthenticated(HttpServletRequest req) {
        final String authHeader = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.isBlank(authHeader)) {
            LOGGER.debug("No Authorization header provided");
            return false;
        }

        final String[] headerParts = authHeader.split("\\s");
        if (headerParts.length != 2 || !"basic".equalsIgnoreCase(headerParts[0])) {
            LOGGER.debug("Invalid Authorization header format");
            return false;
        }

        final String credentials;
        try {
            final byte[] credentialsBytes = Base64.getUrlDecoder().decode(headerParts[1]);
            credentials = new String(credentialsBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            LOGGER.debug("Decoding basic auth credentials failed", e);
            return false;
        }

        final String[] credentialsParts = credentials.split(":");
        if (credentialsParts.length != 2) {
            LOGGER.debug("Invalid basic auth credentials format");
            return false;
        }

        return Objects.equals(basicAuthUsername, credentialsParts[0])
                && Objects.equals(basicAuthPassword, credentialsParts[1]);
    }

}
