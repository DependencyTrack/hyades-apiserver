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
package org.dependencytrack;

import alpine.server.AlpineServlet;
import alpine.server.filters.WhitelistUrlFilter;
import alpine.server.persistence.PersistenceManagerFactory;
import jakarta.servlet.DispatcherType;
import org.dependencytrack.cache.CacheManagerBinder;
import org.dependencytrack.cache.CacheManagerInitializer;
import org.dependencytrack.dev.DevServicesInitializer;
import org.dependencytrack.dex.DexEngineBinder;
import org.dependencytrack.dex.DexEngineInitializer;
import org.dependencytrack.event.EventSubsystemInitializer;
import org.dependencytrack.filestorage.FileStorageBinder;
import org.dependencytrack.filestorage.FileStorageInitializer;
import org.dependencytrack.init.InitTaskServletContextListener;
import org.dependencytrack.notification.DefaultNotificationPublisherInitializer;
import org.dependencytrack.notification.NotificationSubsystemInitializer;
import org.dependencytrack.observability.HealthInitializer;
import org.dependencytrack.observability.HealthServlet;
import org.dependencytrack.observability.MetricsInitializer;
import org.dependencytrack.observability.MetricsServlet;
import org.dependencytrack.plugin.PluginInitializer;
import org.dependencytrack.plugin.PluginManagerBinder;
import org.dependencytrack.secret.SecretManagerInitializer;
import org.dependencytrack.tasks.TaskSchedulerInitializer;
import org.eclipse.jetty.ee11.servlet.DefaultServlet;
import org.eclipse.jetty.ee11.servlet.FilterHolder;
import org.eclipse.jetty.ee11.servlet.ServletContextHandler;
import org.eclipse.jetty.ee11.servlet.ServletHandler;
import org.eclipse.jetty.ee11.servlet.ServletHolder;
import org.eclipse.jetty.http.UriCompliance;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.ForwardedRequestCustomizer;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.resource.ResourceFactory;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;

import java.net.URL;
import java.util.EnumSet;

import static org.glassfish.jersey.server.ServerProperties.BV_SEND_ERROR_IN_RESPONSE;
import static org.glassfish.jersey.server.ServerProperties.WADL_FEATURE_DISABLE;

public final class Application {

    private static final Logger LOGGER = LoggerFactory.getLogger(Application.class);

    public static void main(final String[] args) {
        var contextPath = "/";
        var host = "0.0.0.0";
        var port = 8080;
        for (int i = 0; i < args.length - 1; i++) {
            switch (args[i]) {
                case "-context" -> contextPath = args[++i];
                case "-host" -> host = args[++i];
                case "-port" -> port = Integer.parseInt(args[++i]);
            }
        }

        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();

        final var server = new Server();
        server.setStopAtShutdown(true);

        final var httpConfig = new HttpConfiguration();
        httpConfig.addCustomizer(new ForwardedRequestCustomizer());
        httpConfig.setSendServerVersion(false);

        // Enable legacy URI compliance to allow URL encoding in path segments.
        // Must additionally enable decoding of ambiguous URIs in the servlet handler
        // after server start (see below).
        httpConfig.setUriCompliance(UriCompliance.LEGACY);

        final var connector = new ServerConnector(server, new HttpConnectionFactory(httpConfig));
        connector.setHost(host);
        connector.setPort(port);
        server.setConnectors(new Connector[]{connector});

        final var context = new ServletContextHandler();
        context.setContextPath(contextPath);
        context.setErrorHandler((request, response, callback) -> {
            callback.succeeded();
            return true;
        });
        context.setInitParameter("org.eclipse.jetty.servlet.Default.dirAllowed", "false");

        final URL staticUrl = Application.class.getResource("/static");
        if (staticUrl != null) {
            try {
                context.setBaseResource(ResourceFactory.of(context).newResource(staticUrl.toURI()));
            } catch (Exception e) {
                LOGGER.error("Failed to set base resource", e);
                System.exit(-1);
            }
        }

        context.addEventListener(new DevServicesInitializer());
        context.addEventListener(new HealthInitializer());
        context.addEventListener(new MetricsInitializer());
        context.addEventListener(new InitTaskServletContextListener());
        context.addEventListener(new CacheManagerInitializer());
        context.addEventListener(new FileStorageInitializer());
        context.addEventListener(new SecretManagerInitializer());
        context.addEventListener(new PersistenceManagerFactory());
        context.addEventListener(new PluginInitializer());
        context.addEventListener(new DefaultNotificationPublisherInitializer());
        context.addEventListener(new DexEngineInitializer());
        context.addEventListener(new EventSubsystemInitializer());
        context.addEventListener(new TaskSchedulerInitializer());
        context.addEventListener(new NotificationSubsystemInitializer());

        final var whitelistFilter = new FilterHolder(WhitelistUrlFilter.class);
        whitelistFilter.setInitParameter("allowUrls", "/index.html,/api,/health,/metrics,/.well-known");
        whitelistFilter.setInitParameter("forwardTo", "/index.html");
        whitelistFilter.setInitParameter("forwardExcludes", "/api,/health,/metrics");
        context.addFilter(whitelistFilter, "/*", EnumSet.of(DispatcherType.REQUEST));

        final var apiV1Config = new ResourceConfig();
        apiV1Config.packages(
                "alpine.server.filters",
                "alpine.server.resources",
                "org.dependencytrack.filters",
                "org.dependencytrack.resources.v1");
        apiV1Config.register(CacheManagerBinder.class);
        apiV1Config.register(DexEngineBinder.class);
        apiV1Config.register(FileStorageBinder.class);
        apiV1Config.register(PluginManagerBinder.class);
        apiV1Config.register(MultiPartFeature.class);
        apiV1Config.property(BV_SEND_ERROR_IN_RESPONSE, true);
        apiV1Config.property(WADL_FEATURE_DISABLE, true);

        final var apiV1Servlet = new ServletHolder("DependencyTrack", new AlpineServlet(apiV1Config));
        apiV1Servlet.setInitOrder(1);
        context.addServlet(apiV1Servlet, "/api/*");

        final var apiV2Servlet = new ServletHolder("REST-API-v2", new ServletContainer(
                new org.dependencytrack.resources.v2.ResourceConfig()));
        context.addServlet(apiV2Servlet, "/api/v2/*");

        final var healthServlet = new ServletHolder("Health", HealthServlet.class);
        healthServlet.setInitOrder(1);
        context.addServlet(healthServlet, "/health/*");

        final var metricsServlet = new ServletHolder("Metrics", MetricsServlet.class);
        metricsServlet.setInitOrder(1);
        context.addServlet(metricsServlet, "/metrics");

        context.addServlet(new ServletHolder("default", DefaultServlet.class), "/");

        server.setHandler(context);

        try {
            server.start();
        } catch (Exception e) {
            LOGGER.error("Failed to start server", e);
            System.exit(-1);
        }

        for (final var handler : server.getContainedBeans(ServletHandler.class)) {
            handler.setDecodeAmbiguousURIs(true);
        }

        try {
            server.join();
        } catch (InterruptedException e) {
            LOGGER.warn("Interrupted while waiting for server to stop");
        }
    }

}
