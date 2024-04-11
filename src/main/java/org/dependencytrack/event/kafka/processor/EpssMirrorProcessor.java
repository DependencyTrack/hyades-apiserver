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
package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.dependencytrack.event.kafka.processor.api.BatchProcessor;
import org.dependencytrack.event.kafka.processor.exception.ProcessingException;
import org.dependencytrack.model.Epss;
import org.dependencytrack.parser.dependencytrack.EpssModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.mirror.v1.EpssItem;

import java.util.List;


public class EpssMirrorProcessor implements BatchProcessor<String, EpssItem> {

    public static final String PROCESSOR_NAME = "epss.mirror";
    private static final Logger LOGGER = Logger.getLogger(EpssMirrorProcessor.class);

    @Override
    public void process(List<ConsumerRecord<String, EpssItem>> consumerRecords) throws ProcessingException {
        try (QueryManager qm = new QueryManager()) {
            LOGGER.debug("Synchronizing batch of %s mirrored EPSS records.".formatted(consumerRecords.size()));
            List<Epss> epssList = consumerRecords.stream()
                    .map(ConsumerRecord::value)
                    .map(EpssModelConverter::convert)
                    .toList();
            if (!epssList.isEmpty()) {
                qm.synchronizeAllEpss(epssList);
            }
        }
    }
}
