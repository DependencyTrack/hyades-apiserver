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
package org.dependencytrack.event.kafka;

import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.proto.vulnanalysis.v1.ScanCommand;

/**
 * Well-known headers for Kafka events published and / or consumed by Dependency-Track.
 */
public final class KafkaEventHeaders {

    /**
     * Optional header that may be used to communicate the {@link VulnerabilityAnalysisLevel}
     * along with {@link ScanCommand}s for vulnerability analysis.
     */
    public static final String VULN_ANALYSIS_LEVEL = "x-dtrack-vuln-analysis-level";
    public static final String IS_NEW_COMPONENT = "x-dtrack-is-new-component";

}
