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

import alpine.Config;
import alpine.common.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.IntegrityAnalysis;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.repometaanalysis.v1.AnalysisResult;

import java.util.Date;
import java.util.List;

import static org.dependencytrack.model.IntegrityMatchStatus.COMPONENT_MISSING_HASH;
import static org.dependencytrack.model.IntegrityMatchStatus.COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_FAILED;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_PASSED;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_UNKNOWN;

public class IntegrityCheck {

    private static final Logger LOGGER = Logger.getLogger(IntegrityCheck.class);

    public static void performIntegrityCheck(final IntegrityMetaComponent integrityMetaComponent, final AnalysisResult result, final QueryManager qm) {
        if (!Config.getInstance().getPropertyAsBoolean(ConfigKey.INTEGRITY_CHECK_ENABLED)) {
            LOGGER.debug("Integrity check is disabled");
            return;
        }
        //if integritymeta is in result with hashses but component uuid is not present, result has integrity data for existing
        // components. Get components from database and perform integrity check
        if (StringUtils.isBlank(result.getComponent().getUuid())) {
            integrityAnalysisOfExistingComponents(integrityMetaComponent, qm);
            return;
        }
        //check if the object is not null
        final Component component = qm.getObjectByUuid(Component.class, result.getComponent().getUuid());
        if (component == null) {
            LOGGER.debug("Component is not present in database for which Integrity metadata is received so skipping analysis");
            return;
        }
        calculateIntegrityResult(integrityMetaComponent, component, qm);
    }

    private static void integrityAnalysisOfExistingComponents(final IntegrityMetaComponent integrityMetaComponent, final QueryManager qm) {
        if (integrityMetaComponent != null) {
            List<Component> componentList = qm.getComponentsByPurl(integrityMetaComponent.getPurl());
            for (Component component : componentList) {
                LOGGER.debug("calculate integrity for component : " + component.getUuid());
                calculateIntegrityResult(integrityMetaComponent, component, qm);
            }
        }
    }

    private static IntegrityMatchStatus checkHash(String metadataHash, String componentHash) {
        if (StringUtils.isBlank(metadataHash) && StringUtils.isBlank(componentHash)) {
            return COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN;
        }
        if (StringUtils.isBlank(metadataHash)) {
            return HASH_MATCH_UNKNOWN;
        }
        if (StringUtils.isBlank(componentHash)) {
            return COMPONENT_MISSING_HASH;
        }
        return componentHash.equals(metadataHash) ? HASH_MATCH_PASSED : HASH_MATCH_FAILED;
    }

    public static void calculateIntegrityResult(final IntegrityMetaComponent integrityMetaComponent, final Component component, final QueryManager qm) {
        //if integritymetacomponent is  null, try to get it from db
        //it could be that integrity metadata is already in db
        IntegrityMetaComponent metadata = integrityMetaComponent == null ? qm.getIntegrityMetaComponent(component.getPurl().toString()) : integrityMetaComponent;
        if (metadata == null) {
            LOGGER.info("Integrity metadata is null in result and db. Cannot perform integrity analysis");
            return;
        }
        IntegrityMatchStatus md5Status = checkHash(metadata.getMd5(), component.getMd5());
        IntegrityMatchStatus sha1Status = checkHash(metadata.getSha1(), component.getSha1());
        IntegrityMatchStatus sha256Status = checkHash(metadata.getSha256(), component.getSha256());
        IntegrityMatchStatus sha512Status = checkHash(metadata.getSha512(), component.getSha512());

        IntegrityAnalysis integrityAnalysis = qm.getIntegrityAnalysisByComponentUuid(component.getUuid());
        if (integrityAnalysis == null) {
            integrityAnalysis = new IntegrityAnalysis();
            integrityAnalysis.setComponent(component);
        }
        integrityAnalysis.setIntegrityCheckStatus(calculateIntegrityCheckStatus(md5Status, sha1Status, sha256Status, sha512Status));
        integrityAnalysis.setMd5HashMatchStatus(md5Status);
        integrityAnalysis.setSha1HashMatchStatus(sha1Status);
        integrityAnalysis.setSha256HashMatchStatus(sha256Status);
        integrityAnalysis.setSha512HashMatchStatus(sha512Status);
        integrityAnalysis.setUpdatedAt(new Date());
        qm.persist(integrityAnalysis);
    }

    private static IntegrityMatchStatus calculateIntegrityCheckStatus(IntegrityMatchStatus md5Status, IntegrityMatchStatus sha1Status, IntegrityMatchStatus sha256Status, IntegrityMatchStatus sha512Status) {
        if (md5Status == COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN && sha1Status == COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN && sha256Status == COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN && sha512Status == COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN) {
            return COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN;
        } else if ((md5Status == COMPONENT_MISSING_HASH || md5Status == COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN)
                && (sha1Status == COMPONENT_MISSING_HASH || sha1Status == COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN)
                && (sha256Status == COMPONENT_MISSING_HASH || sha256Status == COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN)
                && (sha512Status == COMPONENT_MISSING_HASH || sha512Status == COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN)) {
            return COMPONENT_MISSING_HASH;
        } else if ((md5Status == HASH_MATCH_UNKNOWN || md5Status == COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN)
                && (sha1Status == HASH_MATCH_UNKNOWN || sha1Status == COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN)
                && (sha256Status == HASH_MATCH_UNKNOWN || sha256Status == COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN)
                && (sha512Status == HASH_MATCH_UNKNOWN || sha512Status == COMPONENT_MISSING_HASH_AND_MATCH_UNKNOWN)) {
            return HASH_MATCH_UNKNOWN;
        } else if (md5Status == HASH_MATCH_FAILED || sha1Status == HASH_MATCH_FAILED || sha256Status == HASH_MATCH_FAILED || sha512Status == HASH_MATCH_FAILED) {
            return HASH_MATCH_FAILED;
        } else {
            return HASH_MATCH_PASSED;
        }
    }
}
