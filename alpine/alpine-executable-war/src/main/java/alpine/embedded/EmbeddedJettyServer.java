/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.embedded;

import org.eclipse.jetty.ee11.servlet.ErrorPageErrorHandler;
import org.eclipse.jetty.ee11.servlet.ServletHandler;
import org.eclipse.jetty.ee11.webapp.WebAppContext;
import org.eclipse.jetty.http.UriCompliance;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.ForwardedRequestCustomizer;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.resource.URLResourceFactory;
import org.eclipse.jetty.xml.XmlConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.ProtectionDomain;
import java.util.Properties;

/**
 * The primary class that starts an embedded Jetty server
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public final class EmbeddedJettyServer {

    private static final Logger LOGGER = LoggerFactory.getLogger(EmbeddedJettyServer.class);

    private EmbeddedJettyServer() {
    }

    public static void main(String[] args) {
        final ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();

        try (final InputStream fis = contextClassLoader.getResourceAsStream("alpine-executable-war.version")) {
            final var properties = new Properties();
            properties.load(fis);

            LOGGER.info(
                    "{} v{} ({}) built on: {}",
                    properties.getProperty("name"),
                    properties.getProperty("version"),
                    properties.getProperty("uuid"),
                    properties.getProperty("timestamp"));
        } catch (IOException e) {
            LOGGER.warn("Failed to load version file", e);
        }

        final CliArgs cliArgs = new CliArgs(args);
        final String contextPath = cliArgs.switchValue("-context", "/");
        final String host = cliArgs.switchValue("-host", "0.0.0.0");
        final int port = cliArgs.switchIntegerValue("-port", 8080);

        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();

        final var server = new Server();
        server.setStopAtShutdown(true);

        final var httpConfig = new HttpConfiguration();
        httpConfig.addCustomizer(new ForwardedRequestCustomizer()); // Add support for X-Forwarded headers
        httpConfig.setSendServerVersion(false);

        // Enable legacy (mimicking Jetty 9) URI compliance.
        // This is required to allow URL encoding in path segments, e.g. "/foo/bar%2Fbaz".
        // https://github.com/jetty/jetty.project/issues/12162
        // https://github.com/jetty/jetty.project/issues/11448
        // https://jetty.org/docs/jetty/12/programming-guide/server/compliance.html#uri
        //
        // NB: The setting on its own is not sufficient. Decoding of ambiguous URIs
        // must additionally be enabled in the servlet handler. This can only be done
        // after the server is started, further down below.
        //
        // TODO: Remove this for the next major version bump. Since we're going against Servlet API
        //  here, the only viable long-term solution is to adapt REST APIs to follow Servlet API 6 spec.
        httpConfig.setUriCompliance(UriCompliance.LEGACY);

        final var connectionFactory = new HttpConnectionFactory(httpConfig);
        final var connector = new ServerConnector(server, connectionFactory);
        connector.setHost(host);
        connector.setPort(port);
        server.setConnectors(new Connector[]{connector});

        final var context = new WebAppContext();
        context.setServer(server);
        context.setContextPath(contextPath);
        context.setErrorHandler(new ErrorHandler());
        context.setTempDirectoryPersistent(false);
        context.setInitParameter("org.eclipse.jetty.servlet.Default.dirAllowed", "false");
        context.setAttribute("org.eclipse.jetty.server.webapp.ContainerIncludeJarPattern", ".*/[^/]*taglibs.*\\.jar$");
        context.setThrowUnavailableOnStartupException(true);

        // Prevent loading of logging classes
        context.getProtectedClassMatcher().add("org.apache.log4j.");
        context.getProtectedClassMatcher().add("org.slf4j.");
        context.getProtectedClassMatcher().add("org.apache.commons.logging.");

        final ProtectionDomain protectionDomain = EmbeddedJettyServer.class.getProtectionDomain();
        final URL location = protectionDomain.getCodeSource().getLocation();
        context.setWar(location.toExternalForm());

        // Allow applications to customize the WebAppContext via Jetty context XML file.
        // An example use-case is the customization of JARs that Jetty shall scan for annotations.
        //
        // https://jetty.org/docs/jetty/12/operations-guide/xml/index.html
        // https://jetty.org/docs/jetty/12/operations-guide/annotations/index.html
        final URL jettyContextUrl = contextClassLoader.getResource("WEB-INF/jetty-context.xml");
        if (jettyContextUrl != null) {
            LOGGER.debug("Applying Jetty customization from {}", jettyContextUrl);
            final Resource jettyContextResource = new URLResourceFactory().newResource(jettyContextUrl);
            try {
                final var xmlConfiguration = new XmlConfiguration(jettyContextResource);
                xmlConfiguration.configure(context);
            } catch (Exception e) {
                LOGGER.error("Failed to apply XML context configuration", e);
                System.exit(-1);
            }
        }

        server.setHandler(context);

        try {
            server.start();
        } catch (Exception e) {
            LOGGER.error("Failed to start server", e);
            System.exit(-1);
        }

        for (final var handler : server.getContainedBeans(ServletHandler.class)) {
            LOGGER.debug("Enabling decoding of ambiguous URIs for servlet handler: {}", handler.getClass().getName());
            handler.setDecodeAmbiguousURIs(true);
        }

        try {
            server.join();
        } catch (InterruptedException e) {
            LOGGER.warn("Interrupted while waiting for server to stop");
        }
    }

    /**
     * Dummy error handler that disables any error pages or jetty related messages and an empty page with a status code.
     */
    private static class ErrorHandler extends ErrorPageErrorHandler {

        @Override
        public boolean handle(Request request, Response response, Callback callback) {
            callback.succeeded();
            return true;
        }

    }

}
