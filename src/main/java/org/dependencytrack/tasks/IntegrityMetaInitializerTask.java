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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.IntegrityMetaInitializerEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;

import java.util.List;

import static org.dependencytrack.event.kafka.componentmeta.RepoMetaConstants.SUPPORTED_PACKAGE_URLS_FOR_INTEGRITY_CHECK;
import static org.dependencytrack.proto.repometaanalysis.v1.FetchMeta.FETCH_META_INTEGRITY_DATA;

public class IntegrityMetaInitializerTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(IntegrityMetaInitializerTask.class);

    private final KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();

    public void inform(final Event e) {
        if (e instanceof IntegrityMetaInitializerEvent) {
            if (!Config.getInstance().getPropertyAsBoolean(ConfigKey.INTEGRITY_INITIALIZER_ENABLED)) {
                LOGGER.debug("Integrity initializer is disabled");
                return;
            }
            try (final var qm = new QueryManager()) {
                batchProcessPurls(qm);
            }
        }
    }

    private void batchProcessPurls(QueryManager qm) {
        long offset = 0;
        List<IntegrityMetaComponent> integrityMetaPurls = qm.fetchNextPurlsPage(offset);
        while (!integrityMetaPurls.isEmpty()) {
            dispatchPurls(qm, integrityMetaPurls);
            qm.batchUpdateIntegrityMetaComponent(integrityMetaPurls);
            offset += integrityMetaPurls.size();
            integrityMetaPurls = qm.fetchNextPurlsPage(offset);
        }
    }

    private void dispatchPurls(QueryManager qm, List<IntegrityMetaComponent> integrityMetaComponents) {
        for (final IntegrityMetaComponent integrityMetaComponent : integrityMetaComponents) {
            try {
                PackageURL purl = new PackageURL(integrityMetaComponent.getPurl());
                //dispatch for integrity metadata only if purl type is supported
                if (SUPPORTED_PACKAGE_URLS_FOR_INTEGRITY_CHECK.contains(purl.getType())) {
                    IntegrityMetaInitializerTask.ComponentProjection componentProjection = qm.getComponentByPurl(integrityMetaComponent.getPurl());
                    if (componentProjection == null) {
                        LOGGER.debug("No component with PURL %s exists (anymore); Skipping".formatted(integrityMetaComponent.getPurl()));
                        continue;
                    }
                    LOGGER.debug("Dispatching purl for integrity metadata: " + integrityMetaComponent.getPurl());
                    //Initializer will not trigger Integrity Check on component so component uuid is not required
                    kafkaEventDispatcher.dispatchEvent(new ComponentRepositoryMetaAnalysisEvent(null, integrityMetaComponent.getPurl(), componentProjection.internal(), FETCH_META_INTEGRITY_DATA));
                }
            } catch (MalformedPackageURLException packageURLException) {
                LOGGER.warn("Initializer cannot dispatch for integrity because purl cannot be parse: " + integrityMetaComponent.getPurl());
                //skip malformed url
            }
        }
    }

    public record ComponentProjection(String purlCoordinates, Boolean internal) {
    }
}
