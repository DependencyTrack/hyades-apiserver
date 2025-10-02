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
import org.dependencytrack.model.CsafDocumentEntity;
import org.dependencytrack.parser.dependencytrack.CsafModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.mirror.v1.CsafDocumentItem;

import java.util.List;

/**
 * This processor takes in items of type {@link CsafDocumentItem} that are produced by the
 * mirror-service and persists them into the database.
 */
public class CsafMirrorProcessor implements BatchProcessor<String, CsafDocumentItem> {

    public static final String PROCESSOR_NAME = "csaf.mirror";
    public static final String PUBLISHERNAMESPACE_PROPERTY_NAME = "dependency-track:vuln:csaf:publisher";
    public static final String TRACKINGID_PROPERTY_NAME = "dependency-track:vuln:csaf:trackingId";
    private static final Logger LOGGER = Logger.getLogger(CsafMirrorProcessor.class);

    @Override
    public void process(List<ConsumerRecord<String, CsafDocumentItem>> consumerRecords) throws ProcessingException {
        try (QueryManager qm = new QueryManager()) {
            LOGGER.debug("Synchronizing batch of %s mirrored CSAF records.".formatted(consumerRecords.size()));
            List<CsafDocumentEntity> list = consumerRecords.stream()
                    .map(ConsumerRecord::value)
                    .map(CsafModelConverter::convert)
                    .toList();
            if (!list.isEmpty()) {
                qm.synchronizeAllCsafDocuments(list);
            }
        }
    }
}
