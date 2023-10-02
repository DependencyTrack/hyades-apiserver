package org.dependencytrack.integrity;

import alpine.Config;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.IntegrityAnalysis;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;

import java.util.Date;

import static org.dependencytrack.model.IntegrityMatchStatus.COMPONENT_MISSING_HASH;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_PASSED;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_UNKNOWN;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_FAILED;

public class IntegrityCheck {

    public void performIntegrityCheck(Component component) {
        if(!Config.getInstance().getPropertyAsBoolean(ConfigKey.INTEGRITY_CHECK_ENABLED)) {
           return;
        }
        try(final var qm = new QueryManager()) {
            final IntegrityMetaComponent metadata = qm.getIntegrityMetaComponent(component.getPurl().toString());
            IntegrityMatchStatus md5Status = checkHash(metadata.getMd5(), component.getMd5());
            IntegrityMatchStatus sha1Status = checkHash(metadata.getSha1(), component.getSha1());
            IntegrityMatchStatus sha256Status = checkHash(metadata.getSha256(), component.getSha256());
            //TODO check if integrity meta table should capture sha512 also

            IntegrityAnalysis integrityAnalysis = qm.getIntegrityAnalysisByComponentUuid(component.getUuid());
            if(integrityAnalysis == null) {
                integrityAnalysis = new IntegrityAnalysis();
                integrityAnalysis.setComponent(component);
            }
            integrityAnalysis.setIntegrityCheckPassed(hasIntegrityCheckPassed(md5Status, sha1Status, sha256Status));
            integrityAnalysis.setMd5HashMatchStatus(md5Status);
            integrityAnalysis.setSha1HashMatchStatus(sha1Status);
            integrityAnalysis.setSha256HashMatchStatus(sha256Status);
            integrityAnalysis.setUpdatedAt(new Date());
            qm.persist(integrityAnalysis);
        }
    }

    private static IntegrityMatchStatus checkHash(String metadataHash, String componentHash) {
        if(metadataHash == null) {
            return HASH_MATCH_UNKNOWN;
        }
        if (componentHash == null) {
            return COMPONENT_MISSING_HASH;
        }
        return componentHash.equals(metadataHash) ? HASH_MATCH_PASSED : HASH_MATCH_FAILED;
    }

    private static boolean hasIntegrityCheckPassed(IntegrityMatchStatus md5Status, IntegrityMatchStatus sha1Status, IntegrityMatchStatus sha256Status) {
        //only fail when either of the check failed or all hashes were missing when at least one
        //was available in repository
        if(md5Status == HASH_MATCH_FAILED || sha1Status == HASH_MATCH_FAILED || sha256Status == HASH_MATCH_FAILED
                || (md5Status == COMPONENT_MISSING_HASH && sha1Status == COMPONENT_MISSING_HASH && sha256Status == COMPONENT_MISSING_HASH)) {
            return false;
        } else {
            return true;
        }
    }
}
