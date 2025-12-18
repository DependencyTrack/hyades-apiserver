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

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.cyclonedx.parsers.BomParserFactory;
import org.cyclonedx.parsers.Parser;
import org.dependencytrack.event.VexUploadEvent;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vex;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.JdoNotificationEmitter;
import org.dependencytrack.notification.NotificationModelConverter;
import org.dependencytrack.parser.cyclonedx.CycloneDXVexImporter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.CompressUtil;

import java.util.Date;
import java.util.List;

import static org.dependencytrack.notification.api.NotificationFactory.createVexConsumedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createVexProcessedNotification;

/**
 * Subscriber task that performs processing of VEX when it is uploaded.
 *
 * @author Steve Springett
 * @since 4.5.0
 */
public class VexUploadProcessingTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(VexUploadProcessingTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof VexUploadEvent) {
            final VexUploadEvent event = (VexUploadEvent) e;
            final byte[] vexBytes = CompressUtil.optionallyDecompress(event.getVex());
            try(final QueryManager qm = new QueryManager()) {
                final Project project = qm.getObjectByUuid(Project.class, event.getProjectUuid());
                final List<Vulnerability> vulnerabilities;

                final Vex vex = new Vex();
                vex.setProject(project);
                vex.setImported(new Date());

                if (BomParserFactory.looksLikeCycloneDX(vexBytes)) {
                    if (qm.isEnabled(ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX)) {
                        LOGGER.info("Processing CycloneDX VEX uploaded to project: " + event.getProjectUuid());
                        vex.setVexFormat(Vex.Format.CYCLONEDX);
                        final Parser parser = BomParserFactory.createParser(vexBytes);
                        final org.cyclonedx.model.Bom cycloneDxBom = parser.parse(vexBytes);
                        vex.setSpecVersion(cycloneDxBom.getSpecVersion());
                        vex.setVexVersion(cycloneDxBom.getVersion());
                        vex.setSerialNumber(cycloneDxBom.getSerialNumber());
                        final CycloneDXVexImporter vexImporter = new CycloneDXVexImporter();
                        vexImporter.applyVex(qm, cycloneDxBom, project);
                        LOGGER.info("Completed processing of CycloneDX VEX for project: " + event.getProjectUuid());
                    } else {
                        LOGGER.warn("A CycloneDX VEX was uploaded but accepting CycloneDX format is disabled. Aborting");
                        return;
                    }
                    // TODO: Add support for CSAF
                } else {
                    LOGGER.warn("The VEX uploaded is not in a supported format. Supported formats include CycloneDX XML and JSON");
                    return;
                }

                final var notificationEmitter = new JdoNotificationEmitter(qm);

                notificationEmitter.emit(
                        createVexConsumedNotification(
                                NotificationModelConverter.convert(project),
                                NotificationModelConverter.convert(vex)));
                qm.persist(vex);

                notificationEmitter.emit(
                        createVexProcessedNotification(
                                NotificationModelConverter.convert(project),
                                NotificationModelConverter.convert(vex)));
            } catch (Exception ex) {
                LOGGER.error("Error while processing vex", ex);
            }
        }
    }
}
