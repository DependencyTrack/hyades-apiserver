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
package org.dependencytrack.event.kafka.componentmeta;

import com.github.packageurl.MalformedPackageURLException;
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;

import java.time.Instant;
import java.util.Date;

import static org.dependencytrack.event.kafka.componentmeta.RepoMetaConstants.TIME_SPAN;
import static org.dependencytrack.model.FetchStatus.NOT_AVAILABLE;
import static org.dependencytrack.model.FetchStatus.PROCESSED;

public class SupportedMetaHandler extends AbstractMetaHandler {

    public SupportedMetaHandler(ComponentProjection componentProjection, QueryManager queryManager, KafkaEventDispatcher kafkaEventDispatcher, FetchMeta fetchMeta) {
        this.componentProjection = componentProjection;
        this.kafkaEventDispatcher = kafkaEventDispatcher;
        this.queryManager = queryManager;
        this.fetchMeta = fetchMeta;
    }

    @Override
    public IntegrityMetaComponent handle() throws MalformedPackageURLException {
        IntegrityMetaComponent persistentIntegrityMetaComponent = queryManager.getIntegrityMetaComponent(componentProjection.purl().toString());
        if (persistentIntegrityMetaComponent == null) {
            IntegrityMetaComponent integrityMetaComponent = queryManager.createIntegrityMetaComponent(createIntegrityMetaComponent(componentProjection.purl().toString()));
            kafkaEventDispatcher.dispatchEvent(new ComponentRepositoryMetaAnalysisEvent(componentProjection.componentUuid(), componentProjection.purl().canonicalize(), componentProjection.internal(), fetchMeta));
            return integrityMetaComponent;
        }
        if (persistentIntegrityMetaComponent.getStatus() == PROCESSED || persistentIntegrityMetaComponent.getStatus() == NOT_AVAILABLE) {
            //only fetch the latest version because integrity data (hashes) is present
            kafkaEventDispatcher.dispatchEvent(new ComponentRepositoryMetaAnalysisEvent(componentProjection.componentUuid(), componentProjection.purl().canonicalize(), componentProjection.internal(), FetchMeta.FETCH_META_LATEST_VERSION));
            return persistentIntegrityMetaComponent;
        }
        if (persistentIntegrityMetaComponent.getStatus() == null || (persistentIntegrityMetaComponent.getStatus() == FetchStatus.IN_PROGRESS && Date.from(Instant.now()).getTime() - persistentIntegrityMetaComponent.getLastFetch().getTime() > TIME_SPAN)) {
            persistentIntegrityMetaComponent.setLastFetch(Date.from(Instant.now()));
            IntegrityMetaComponent updateIntegrityMetaComponent = queryManager.updateIntegrityMetaComponent(persistentIntegrityMetaComponent);
            kafkaEventDispatcher.dispatchEvent(new ComponentRepositoryMetaAnalysisEvent(componentProjection.componentUuid(), componentProjection.purl().canonicalize(), componentProjection.internal(), fetchMeta));
            return updateIntegrityMetaComponent;
        } else {
            kafkaEventDispatcher.dispatchEvent(new ComponentRepositoryMetaAnalysisEvent(componentProjection.componentUuid(), componentProjection.purl().canonicalize(), componentProjection.internal(), fetchMeta));
            return persistentIntegrityMetaComponent;
        }
    }
}