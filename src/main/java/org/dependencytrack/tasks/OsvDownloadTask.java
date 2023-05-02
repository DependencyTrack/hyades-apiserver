package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.persistence.QueryManager;
import org.apache.http.HttpStatus;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;
import java.util.Set;
import java.util.stream.Collectors;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;

public class OsvDownloadTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(OsvDownloadTask.class);
    private String osvBaseUrl;
    private Set<String> ecosystems;

    public OsvDownloadTask() {
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getGroupName(), VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getPropertyName());
            if (enabled != null) {
                final String ecosystemConfig = enabled.getPropertyValue();
                if (ecosystemConfig != null) {
                    ecosystems = Arrays.stream(ecosystemConfig.split(";")).map(String::trim).collect(Collectors.toSet());
                }
                this.osvBaseUrl = qm.getConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getGroupName(), VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getPropertyName()).getPropertyValue();
                if (this.osvBaseUrl != null && !this.osvBaseUrl.endsWith("/")) {
                    this.osvBaseUrl += "/";
                }
            }
        }
    }

    @Override
    public void inform(Event e) {
        if (e instanceof OsvMirrorEvent) {
            if (this.ecosystems != null && !this.ecosystems.isEmpty()) {
                new KafkaEventDispatcher().dispatchBlocking(new OsvMirrorEvent(String.join(",", ecosystems)));
            }
            else {
                LOGGER.info("Google OSV mirroring is disabled. No ecosystem selected.");
            }
        }
    }

    public Set<String> getEnabledEcosystems() {
        return Optional.ofNullable(this.ecosystems)
                .orElseGet(Collections::emptySet);
    }

    public List<String> getEcosystems() {
        ArrayList<String> ecosystems = new ArrayList<>();
        String url = this.osvBaseUrl + "ecosystems.txt";
        HttpUriRequest request = new HttpGet(url);
        try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            final StatusLine status = response.getStatusLine();
            if (status.getStatusCode() == HttpStatus.SC_OK) {
                try (InputStream in = response.getEntity().getContent();
                     Scanner scanner = new Scanner(in, StandardCharsets.UTF_8)) {
                    while (scanner.hasNextLine()) {
                        final String line = scanner.nextLine();
                        if(!line.isBlank()) {
                            ecosystems.add(line.trim());
                        }
                    }
                }
            } else {
                LOGGER.error("Ecosystem download failed : " + status.getStatusCode() + ": " + status.getReasonPhrase());
            }
        } catch (Exception ex) {
            LOGGER.error("Exception while executing Http request for ecosystems", ex);
        }
        return ecosystems;
    }
}