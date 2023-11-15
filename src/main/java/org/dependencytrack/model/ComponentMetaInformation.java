package org.dependencytrack.model;

import java.util.Date;

public record ComponentMetaInformation(Date publishedDate, IntegrityMatchStatus integrityMatchStatus,
                                       Date lastFetched,
                                       String integrityRepoUrl) {
}
