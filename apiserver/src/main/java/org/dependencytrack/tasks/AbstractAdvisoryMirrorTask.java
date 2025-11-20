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
package org.dependencytrack.tasks;

import alpine.event.framework.Event;
import org.cyclonedx.proto.v1_6.Bom;
import org.dependencytrack.model.Advisory;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.dependencytrack.BovModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.dependencytrack.datasource.vuln.csaf.CycloneDxPropertyNames.PROPERTY_ADVISORY_FORMAT;
import static org.dependencytrack.datasource.vuln.csaf.CycloneDxPropertyNames.PROPERTY_ADVISORY_JSON;
import static org.dependencytrack.datasource.vuln.csaf.CycloneDxPropertyNames.PROPERTY_ADVISORY_NAME;
import static org.dependencytrack.datasource.vuln.csaf.CycloneDxPropertyNames.PROPERTY_ADVISORY_PUBLISHER_NAMESPACE;
import static org.dependencytrack.datasource.vuln.csaf.CycloneDxPropertyNames.PROPERTY_ADVISORY_TITLE;
import static org.dependencytrack.datasource.vuln.csaf.CycloneDxPropertyNames.PROPERTY_ADVISORY_UPDATED;
import static org.dependencytrack.datasource.vuln.csaf.CycloneDxPropertyNames.PROPERTY_ADVISORY_URL;
import static org.dependencytrack.datasource.vuln.csaf.CycloneDxPropertyNames.PROPERTY_ADVISORY_VERSION;
import static org.dependencytrack.datasource.vuln.csaf.CycloneDxPropertyNames.extractProperty;

/**
 * An abstract task that mirrors advisory-based vulnerability data sources. These data sources can
 * contain multiple vulnerabilities per advisory, and the advisory itself is a first-class entity.
 *
 * @since 5.7.0
 */
public abstract class AbstractAdvisoryMirrorTask extends AbstractVulnDataSourceMirrorTask {

    AbstractAdvisoryMirrorTask(PluginManager pluginManager, Class<? extends Event> eventClass, String vulnDataSourceExtensionName, Vulnerability.Source source) {
        super(pluginManager, eventClass, vulnDataSourceExtensionName, source);
    }

    @Override
    protected void processBatch(final VulnDataSource dataSource, final Collection<Bom> bovs) {
        logger.debug("Processing batch of {} BOVs", bovs.size());

        try (final var qm = new QueryManager()) {
            qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");

            qm.runInTransaction(() -> {
                for (final Bom bov : bovs) {
                    final var advisory = new Advisory();
                    advisory.setTitle(extractProperty(bov, PROPERTY_ADVISORY_TITLE, String.class));
                    advisory.setLastFetched(extractProperty(bov, PROPERTY_ADVISORY_UPDATED, Instant.class));
                    advisory.setContent(extractProperty(bov, PROPERTY_ADVISORY_JSON, String.class));
                    advisory.setName(extractProperty(bov, PROPERTY_ADVISORY_NAME, String.class));
                    advisory.setVersion(extractProperty(bov, PROPERTY_ADVISORY_VERSION, String.class));
                    advisory.setPublisher(extractProperty(bov, PROPERTY_ADVISORY_PUBLISHER_NAMESPACE, String.class));
                    advisory.setUrl(extractProperty(bov, PROPERTY_ADVISORY_URL, String.class));
                    advisory.setFormat(extractProperty(bov, PROPERTY_ADVISORY_FORMAT, String.class));

                    for (final var v : bov.getVulnerabilitiesList()) {
                        final Vulnerability vuln = BovModelConverter.convert(bov, v, true);
                        final List<VulnerableSoftware> vsList = BovModelConverter.extractVulnerableSoftware(bov);

                        logger.debug("Synchronizing vulnerability {}", vuln.getVulnId());
                        final Vulnerability persistentVuln = qm.synchronizeVulnerability(vuln, false);
                        qm.synchronizeVulnerableSoftware(persistentVuln, vsList, this.source);

                        advisory.addVulnerability(persistentVuln);
                    }

                    logger.debug("Synchronizing advisory {}", advisory.getTitle());
                    qm.synchronizeAdvisory(advisory);
                }
            });
        }

        for (final Bom bov : bovs) {
            dataSource.markProcessed(bov);
        }
    }

}
