package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import kong.unirest.json.JSONObject;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.osv.OsvAdvisoryParser;
import org.dependencytrack.parser.osv.model.OsvAdvisory;
import org.dependencytrack.parser.osv.model.OsvAffectedPackage;
import org.dependencytrack.persistence.QueryManager;
import us.springett.cvss.Cvss;
import us.springett.cvss.Score;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;
import static org.dependencytrack.model.Severity.getSeverityByLevel;
import static org.dependencytrack.util.VulnerabilityUtil.normalizedCvssV2Score;
import static org.dependencytrack.util.VulnerabilityUtil.normalizedCvssV3Score;

public class OsvDownloadTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(OsvDownloadTask.class);
    private String ecosystemConfig;
    private List<String> ecosystems;

    private final KafkaEventDispatcher kafkaEventDispatcher;

    public List<String> getEnabledEcosystems() {
        return this.ecosystems;
    }

    public OsvDownloadTask() {
        this(new KafkaEventDispatcher());
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getGroupName(), VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getPropertyName());
            if (enabled != null) {
                this.ecosystemConfig = enabled.getPropertyValue();
                if (this.ecosystemConfig != null) {
                    ecosystems = Arrays.stream(this.ecosystemConfig.split(";")).map(String::trim).toList();
                }
            }
        }
    }
    OsvDownloadTask(final KafkaEventDispatcher kafkaEventDispatcher) {
        this.kafkaEventDispatcher = kafkaEventDispatcher;
    }

    @Override
    public void inform(Event e) {
        if (e instanceof OsvMirrorEvent) {
            if (this.ecosystems != null && !this.ecosystems.isEmpty()) {
                for (String ecosystem : this.ecosystems) {
                    kafkaEventDispatcher.dispatchOsvMirror(ecosystem);
                }
            }
            else {
                LOGGER.info("Google OSV mirroring is disabled. No ecosystem selected.");
            }
        }
    }
}