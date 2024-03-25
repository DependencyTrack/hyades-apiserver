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
package org.dependencytrack.persistence.jdbi.mapping;

import org.dependencytrack.proto.notification.v1.Component;
import org.dependencytrack.proto.notification.v1.NewVulnerableDependencySubject;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.Vulnerability;
import org.jdbi.v3.core.result.RowReducer;
import org.jdbi.v3.core.result.RowView;

import java.util.stream.Stream;

public class NotificationSubjectNewVulnerableDependencyRowReducer
        implements RowReducer<NewVulnerableDependencySubject.Builder, NewVulnerableDependencySubject> {

    @Override
    public NewVulnerableDependencySubject.Builder container() {
        return NewVulnerableDependencySubject.newBuilder();
    }

    @Override
    public void accumulate(final NewVulnerableDependencySubject.Builder container, final RowView rowView) {
        if (!container.hasComponent()) {
            container.setComponent(rowView.getRow(Component.class));
        }
        if (!container.hasProject()) {
            container.setProject(rowView.getRow(Project.class));
        }
        container.addVulnerabilities(rowView.getRow(Vulnerability.class));
    }

    @Override
    public Stream<NewVulnerableDependencySubject> stream(final NewVulnerableDependencySubject.Builder container) {
        return Stream.of(container.build());
    }

}
