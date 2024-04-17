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

import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;

import java.time.Instant;
import java.util.Date;

public abstract class AbstractMetaHandler implements Handler {

    ComponentProjection componentProjection;
    QueryManager queryManager;
    KafkaEventDispatcher kafkaEventDispatcher;
    FetchMeta fetchMeta;


    public static IntegrityMetaComponent createIntegrityMetaComponent(String purl) {
        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setStatus(FetchStatus.IN_PROGRESS);
        integrityMetaComponent.setPurl(purl);
        integrityMetaComponent.setLastFetch(Date.from(Instant.now()));
        return integrityMetaComponent;
    }

}