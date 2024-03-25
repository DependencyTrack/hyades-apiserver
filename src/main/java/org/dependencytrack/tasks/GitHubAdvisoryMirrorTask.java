package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import org.dependencytrack.event.GitHubAdvisoryMirrorEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.persistence.QueryManager;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;

public class GitHubAdvisoryMirrorTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(GitHubAdvisoryMirrorTask.class);
    private final boolean isEnabled;
    private String accessToken;

    public GitHubAdvisoryMirrorTask() {
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getGroupName(), VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getPropertyName());
            this.isEnabled = enabled != null && Boolean.valueOf(enabled.getPropertyValue());
            final ConfigProperty accessToken = qm.getConfigProperty(VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN.getGroupName(), VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN.getPropertyName());
            if (accessToken != null) {
                this.accessToken = accessToken.getPropertyValue();
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof GitHubAdvisoryMirrorEvent && this.isEnabled) {
            if (this.accessToken != null) {
                LOGGER.info("Starting GitHub Advisory mirroring task");
                new KafkaEventDispatcher().dispatchBlocking(new GitHubAdvisoryMirrorEvent());
            } else {
                LOGGER.warn("GitHub Advisory mirroring is enabled, but no personal access token is configured. Skipping.");
            }
        }
    }
}
