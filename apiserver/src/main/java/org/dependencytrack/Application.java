package org.dependencytrack;

import alpine.server.AlpineServlet;
import alpine.server.metrics.MetricsInitializer;
import alpine.server.persistence.PersistenceManagerFactory;
import alpine.server.servlets.HealthServlet;
import alpine.server.servlets.MetricsServlet;
import org.dependencytrack.common.KeyManagerInitializer;
import org.dependencytrack.dev.DevServicesInitializer;
import org.dependencytrack.event.EventSubsystemInitializer;
import org.dependencytrack.event.PurlMigrator;
import org.dependencytrack.event.kafka.KafkaProducerInitializer;
import org.dependencytrack.event.kafka.processor.ProcessorInitializer;
import org.dependencytrack.health.HealthCheckInitializer;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.dependencytrack.persistence.MigrationInitializer;
import org.dependencytrack.plugin.PluginInitializer;
import org.eclipse.jetty.ee10.servlet.ErrorPageErrorHandler;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.http.UriCompliance;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.Callback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Application {

    public static final Logger LOGGER = LoggerFactory.getLogger(Application.class);

    public static void main(final String[] args) {
        final Server server = new Server();
        final HttpConfiguration httpConfig = new HttpConfiguration();
        httpConfig.addCustomizer(new org.eclipse.jetty.server.ForwardedRequestCustomizer()); // Add support for X-Forwarded headers

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

        final HttpConnectionFactory connectionFactory = new HttpConnectionFactory(httpConfig);
        final ServerConnector connector = new ServerConnector(server, connectionFactory);
        connector.setHost("0.0.0.0");
        connector.setPort(8080);
        disableServerVersionHeader(connector);
        server.setConnectors(new Connector[]{connector});

        final var contextHandler = new ServletContextHandler();
        contextHandler.setServer(server);
        contextHandler.setContextPath("/");
        contextHandler.setErrorHandler(new ErrorHandler());
        contextHandler.setInitParameter("org.eclipse.jetty.servlet.Default.dirAllowed", "false");
        contextHandler.setAttribute("org.eclipse.jetty.server.webapp.ContainerIncludeJarPattern", "^$");

        contextHandler.addEventListener(new DevServicesInitializer());
        contextHandler.addEventListener(new MetricsInitializer());
        contextHandler.addEventListener(new KeyManagerInitializer());
        contextHandler.addEventListener(new MigrationInitializer());
        contextHandler.addEventListener(new PersistenceManagerFactory());
        contextHandler.addEventListener(new PluginInitializer());
        contextHandler.addEventListener(new HealthCheckInitializer());
        contextHandler.addEventListener(new DefaultObjectGenerator());
        contextHandler.addEventListener(new KafkaProducerInitializer());
        contextHandler.addEventListener(new EventSubsystemInitializer());
        contextHandler.addEventListener(new ProcessorInitializer());
        contextHandler.addEventListener(new PurlMigrator());

        final ServletHolder appServletHolder = contextHandler.addServlet(AlpineServlet.class, "/api/*");
        appServletHolder.setInitParameter(
                "jersey.config.server.provider.packages",
                "alpine.server.filters,alpine.server.resources,org.dependencytrack.resources,org.dependencytrack.filters");
        appServletHolder.setInitParameter(
                "jersey.config.server.provider.classnames",
                "org.glassfish.jersey.media.multipart.MultiPartFeature");
        appServletHolder.setInitParameter(
                "jersey.config.beanValidation.enableOutputValidationErrorEntity.server",
                "true");

        contextHandler.addServlet(HealthServlet.class, "/health/*");
        contextHandler.addServlet(MetricsServlet.class, "/metrics");

        server.setHandler(contextHandler);
        server.addBean(new ErrorHandler());
        try {
            server.start();
            for (final ServletHandler handler : server.getContainedBeans(ServletHandler.class)) {
                LOGGER.debug("Enabling decoding of ambiguous URIs for servlet handler: {}", handler.getClass().getName());
                handler.setDecodeAmbiguousURIs(true);
            }
            addJettyShutdownHook(server);
            server.join();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    private static void disableServerVersionHeader(Connector connector) {
        connector.getConnectionFactories().stream()
                .filter(cf -> cf instanceof HttpConnectionFactory)
                .forEach(cf -> ((HttpConnectionFactory) cf)
                        .getHttpConfiguration().setSendServerVersion(false));
    }

    /**
     * Dummy error handler that disables any error pages or jetty related messages and an empty page with a status code.
     */
    private static class ErrorHandler extends ErrorPageErrorHandler {
        @Override
        public boolean handle(final Request request, final Response response, final Callback callback) throws Exception {
            response.setStatus(response.getStatus());
            callback.succeeded();
            return true;
        }
    }

    private static void addJettyShutdownHook(final Server server) {
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                try {
                    System.out.println("Shutting down application");
                    server.stop();
                } catch (Exception e) {
                    //System.err.println("Exception occurred shutting down: " + e.getMessage());
                }
            }
        });
    }

}
