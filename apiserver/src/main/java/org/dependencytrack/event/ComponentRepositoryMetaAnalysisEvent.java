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
package org.dependencytrack.event;

import alpine.event.framework.Event;
import org.dependencytrack.model.Component;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;

import java.util.UUID;

/**
 * Defines an {@link Event} triggered when requesting a component to be analyzed for meta information.
 *
 * @param purlCoordinates The package URL coordinates of the {@link Component} to analyze
 * @param internal        Whether the {@link Component} is internal
 * @param fetchMeta       Whether component hash data or component meta data needs to be fetched from external api
 */
public record ComponentRepositoryMetaAnalysisEvent(UUID componentUuid, String purlCoordinates, Boolean internal,
                                                   FetchMeta fetchMeta) implements Event {

}
