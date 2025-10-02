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
package org.dependencytrack.parser.dependencytrack;

import org.dependencytrack.model.CsafDocumentEntity;
import org.dependencytrack.proto.mirror.v1.CsafDocumentItem;

import java.time.Instant;

/**
 * A utility class that converts a {@link CsafDocumentItem} (which is transferred
 * over Kafka) to a {@link CsafDocumentEntity} (which is persisted into the database).
 */
public final class CsafModelConverter {
    public static CsafDocumentEntity convert(final CsafDocumentItem item) {
        final CsafDocumentEntity doc = new CsafDocumentEntity();
        doc.setPublisherNamespace(item.getPublisherNamespace());
        doc.setTrackingID(item.getTrackingId());
        doc.setTrackingVersion(item.getTrackingVersion());
        doc.setName(item.getName());
        doc.setContent(item.getJsonContent().toStringUtf8());
        doc.setSeen(item.getSeen());
        if (item.hasLastFetched()) {
            doc.setLastFetched(Instant.ofEpochSecond(item.getLastFetched().getSeconds()));
        }
        if (item.hasUrl()) {
            doc.setUrl(item.getUrl());
        }

        return doc;
    }
}
