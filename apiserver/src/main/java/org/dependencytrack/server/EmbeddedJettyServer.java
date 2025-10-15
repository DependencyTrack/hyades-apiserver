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
package org.dependencytrack.server;

import alpine.server.AlpineServlet;
import alpine.server.metrics.MetricsInitializer;
import alpine.server.persistence.PersistenceManagerFactory;
import org.dependencytrack.event.EventSubsystemInitializer;
import org.dependencytrack.event.PurlMigrator;
import org.dependencytrack.event.kafka.KafkaProducerInitializer;
import org.dependencytrack.event.kafka.processor.ProcessorInitializer;
import org.dependencytrack.health.HealthCheckInitializer;
import org.dependencytrack.init.InitTaskServletContextListener;
import org.dependencytrack.plugin.PluginInitializer;
import org.dependencytrack.resources.v2.ResourceConfig;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.http.UriCompliance;
import org.eclipse.jetty.server.ForwardedRequestCustomizer;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.util.resource.ResourceFactory;
import org.glassfish.jersey.server.ServerProperties;
import org.glassfish.jersey.servlet.ServletContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * @since 5.7.0
 */
public final class EmbeddedJettyServer {

    private static final Logger LOGGER = LoggerFactory.getLogger(EmbeddedJettyServer.class);

    public static Server create(
            final String host,
            final int port,
            final String contextPath) {
        final var server = new Server();
        server.setStopAtShutdown(true);
        server.setStopTimeout(TimeUnit.SECONDS.toMillis(30));

        final var httpConfig = new HttpConfiguration();
        httpConfig.addCustomizer(new ForwardedRequestCustomizer());
        httpConfig.setSendServerVersion(false);
        httpConfig.setUriCompliance(UriCompliance.LEGACY);

        final var connectionFactory = new HttpConnectionFactory(httpConfig);

        final var connector = new ServerConnector(server, connectionFactory);
        connector.setHost(host);
        connector.setPort(port);
        server.addConnector(connector);

        final var resourceFactory = ResourceFactory.of(server);
        final var staticFileHandler = new ResourceHandler();
        staticFileHandler.setBaseResource(resourceFactory.newClassLoaderResource("/static"));
        staticFileHandler.setDirAllowed(false);
        staticFileHandler.setWelcomeFiles("index.html");
        final var staticContextHandler = new ContextHandler("/");
        staticContextHandler.setHandler(staticFileHandler);

        final var servletContextHandler = new ServletContextHandler("/");
        servletContextHandler.setContextPath(contextPath);
        servletContextHandler.addEventListener(new MetricsInitializer());
        servletContextHandler.addEventListener(new InitTaskServletContextListener());
        servletContextHandler.addEventListener(new PersistenceManagerFactory());
        servletContextHandler.addEventListener(new PluginInitializer());
        servletContextHandler.addEventListener(new HealthCheckInitializer());
        servletContextHandler.addEventListener(new KafkaProducerInitializer());
        servletContextHandler.addEventListener(new EventSubsystemInitializer());
        servletContextHandler.addEventListener(new ProcessorInitializer());
        servletContextHandler.addEventListener(new PurlMigrator());

        final var restApiV1ServletHolder = new ServletHolder("REST-API-v1", AlpineServlet.class);
        restApiV1ServletHolder.setInitParameters(Map.ofEntries(
                Map.entry(
                        ServerProperties.PROVIDER_PACKAGES, """
                                alpine.server.filters,\
                                alpine.server.resources,\
                                org.dependencytrack.filters,\
                                org.dependencytrack.resources.v1"""),
                Map.entry(
                        ServerProperties.PROVIDER_CLASSNAMES,
                        "org.glassfish.jersey.media.multipart.MultiPartFeature"),
                Map.entry(
                        ServerProperties.BV_SEND_ERROR_IN_RESPONSE,
                        "true")));
        servletContextHandler.addServlet(restApiV1ServletHolder, "/api/*");

        final var restApiV2ServletHolder = new ServletHolder(
                "REST-API-v2",
                new ServletContainer(new ResourceConfig()));
        servletContextHandler.addServlet(restApiV2ServletHolder, "/api/v2/*");

        final var handlerCollection = new ContextHandlerCollection();
        handlerCollection.addHandler(staticContextHandler);
        handlerCollection.addHandler(servletContextHandler);
        server.setHandler(handlerCollection);

        return server;
    }

    public static void main(final String[] args) throws Exception {
        final Server server = create("0.0.0.0", 8080, "/");
        server.start();
        server.join();
    }

}
