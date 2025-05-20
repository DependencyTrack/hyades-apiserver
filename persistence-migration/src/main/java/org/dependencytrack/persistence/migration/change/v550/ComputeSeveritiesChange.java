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
package org.dependencytrack.persistence.migration.change.v550;

import liquibase.change.custom.CustomTaskChange;
import liquibase.database.Database;
import liquibase.database.jvm.JdbcConnection;
import liquibase.exception.CustomChangeException;
import liquibase.exception.DatabaseException;
import liquibase.exception.SetupException;
import liquibase.exception.ValidationErrors;
import liquibase.resource.ResourceAccessor;

import java.math.BigDecimal;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;

public class ComputeSeveritiesChange implements CustomTaskChange {

    private int batchSize;
    private int numBatches;
    private int numUpdates;

    @Override
    public void setUp() throws SetupException {
    }

    @Override
    public void execute(final Database database) throws CustomChangeException {
        final var connection = (JdbcConnection) database.getConnection();

        // NB: When generating the schema via `mvn liquibase:updateSQL`, none of the changesets
        // is actually applied. If we don't perform a preliminary check here, schema generation fails.
        try (final PreparedStatement ps = connection.prepareStatement("""
                SELECT 1
                  FROM information_schema.tables
                 WHERE table_schema = current_schema()
                   AND table_name = 'VULNERABILITY'
                """)) {
            if (!ps.executeQuery().next()) {
                // Probably running within `mvn liquibase:updateSQL`.
                return;
            }
        } catch (DatabaseException | SQLException e) {
            throw new CustomChangeException("Failed to check for databasechangelog table", e);
        }

        try (final PreparedStatement selectStatement = connection.prepareStatement("""
                SELECT "CVSSV2BASESCORE"
                     , "CVSSV3BASESCORE"
                     , "OWASPRRLIKELIHOODSCORE"
                     , "OWASPRRTECHNICALIMPACTSCORE"
                     , "OWASPRRBUSINESSIMPACTSCORE"
                     , "VULNID"
                  FROM "VULNERABILITY"
                 WHERE "SEVERITY" IS NULL
                """);
             final PreparedStatement updateStatement = connection.prepareStatement("""
                     UPDATE "VULNERABILITY" SET "SEVERITY" = ? WHERE "VULNID" = ?
                     """)) {
            final ResultSet rs = selectStatement.executeQuery();
            while (rs.next()) {
                final String vulnId = rs.getString(6);
                final Severity severity = getSeverity(
                        rs.getBigDecimal(1),
                        rs.getBigDecimal(2),
                        rs.getBigDecimal(3),
                        rs.getBigDecimal(4),
                        rs.getBigDecimal(5)
                );

                updateStatement.setString(1, severity.name());
                updateStatement.setString(2, vulnId);
                updateStatement.addBatch();
                if (++batchSize == 500) {
                    updateStatement.executeBatch();
                    numUpdates += batchSize;
                    numBatches++;
                    batchSize = 0;
                }
            }

            if (batchSize > 0) {
                updateStatement.executeBatch();
                numUpdates += batchSize;
                numBatches++;
            }
        } catch (DatabaseException | SQLException e) {
            throw new CustomChangeException("Failed to update severities", e);
        }
    }

    @Override
    public String getConfirmationMessage() {
        return "Updated %d vulnerabilities in %d batches".formatted(numUpdates, numBatches);
    }

    @Override
    public void setFileOpener(final ResourceAccessor resourceAccessor) {
    }

    @Override
    public ValidationErrors validate(final Database database) {
        return null;
    }

    // NB: Copied from org.dependencytrack.model.Severity
    private enum Severity {

        CRITICAL (5),
        HIGH (4),
        MEDIUM (3),
        LOW (2),
        INFO (1),
        UNASSIGNED (0);

        private final int level;

        Severity(final int level) {
            this.level = level;
        }

        public int getLevel() {
            return level;
        }

    }

    // NB: Copied from org.dependencytrack.util.VulnerabilityUtil.
    private static Severity getSeverity(final BigDecimal cvssV2BaseScore, final BigDecimal cvssV3BaseScore, final BigDecimal owaspRRLikelihoodScore, final BigDecimal owaspRRTechnicalImpactScore, final BigDecimal owaspRRBusinessImpactScore) {
        Severity severity = Severity.UNASSIGNED;
        Severity cvssSeverity = null, owaspRRSeverity = null;
        if (cvssV3BaseScore != null) {
            cvssSeverity = normalizedCvssV3Score(cvssV3BaseScore.doubleValue());
        } else if (cvssV2BaseScore != null) {
            cvssSeverity = normalizedCvssV2Score(cvssV2BaseScore.doubleValue());
        }

        if (owaspRRLikelihoodScore != null && owaspRRTechnicalImpactScore != null && owaspRRBusinessImpactScore != null) {
            owaspRRSeverity = normalizedOwaspRRScore(owaspRRLikelihoodScore.doubleValue(), owaspRRTechnicalImpactScore.doubleValue(), owaspRRBusinessImpactScore.doubleValue());
        }

        if (owaspRRSeverity != null && cvssSeverity != null) {
            severity = owaspRRSeverity.getLevel() > cvssSeverity.getLevel() ? owaspRRSeverity : cvssSeverity;
        } else if (owaspRRSeverity != null) {
            severity = owaspRRSeverity;
        } else if (cvssSeverity != null) {
            severity = cvssSeverity;
        }

        return severity;
    }

    private static Severity normalizedCvssV2Score(final double score) {
        if (score >= 7) {
            return Severity.HIGH;
        } else if (score >= 4) {
            return Severity.MEDIUM;
        } else if (score > 0) {
            return Severity.LOW;
        } else {
            return Severity.UNASSIGNED;
        }
    }

    private static Severity normalizedCvssV3Score(final double score) {
        if (score >= 9) {
            return Severity.CRITICAL;
        } else if (score >= 7) {
            return Severity.HIGH;
        } else if (score >= 4) {
            return Severity.MEDIUM;
        } else if (score > 0) {
            return Severity.LOW;
        } else {
            return Severity.UNASSIGNED;
        }
    }

    private static final Map<Severity, Map<Severity, Severity>> OWASP_RR_LIKELIHOOD_TO_IMPACT_SEVERITY_MATRIX = Map.of(
            Severity.LOW, Map.of(
                    Severity.LOW, Severity.INFO,
                    Severity.MEDIUM, Severity.LOW,
                    Severity.HIGH, Severity.MEDIUM,
                    Severity.UNASSIGNED, Severity.UNASSIGNED
            ),
            Severity.MEDIUM, Map.of(
                    Severity.LOW, Severity.LOW,
                    Severity.MEDIUM, Severity.MEDIUM,
                    Severity.HIGH, Severity.HIGH,
                    Severity.UNASSIGNED, Severity.UNASSIGNED
            ),
            Severity.HIGH, Map.of(
                    Severity.LOW, Severity.MEDIUM,
                    Severity.MEDIUM, Severity.HIGH,
                    Severity.HIGH, Severity.CRITICAL,
                    Severity.UNASSIGNED, Severity.UNASSIGNED
            ),
            Severity.UNASSIGNED, Map.of(
                    Severity.LOW, Severity.UNASSIGNED,
                    Severity.MEDIUM, Severity.UNASSIGNED,
                    Severity.HIGH, Severity.UNASSIGNED,
                    Severity.UNASSIGNED, Severity.UNASSIGNED
            )
    );

    private static Severity normalizedOwaspRRScore(final double likelihoodScore, final double technicalImpactScore, final double businessImpactScore) {
        double impactScore = Math.max(technicalImpactScore, businessImpactScore);
        Severity likelihoodSeverity = normalizedOwaspRRScore(likelihoodScore);
        Severity impactSeverity = normalizedOwaspRRScore(impactScore);
        return OWASP_RR_LIKELIHOOD_TO_IMPACT_SEVERITY_MATRIX.get(likelihoodSeverity).get(impactSeverity);
    }

    private static Severity normalizedOwaspRRScore(final double score) {
        if (score >= 6) {
            return Severity.HIGH;
        } else if (score >= 3) {
            return Severity.MEDIUM;
        } else if (score > 0) {
            return Severity.LOW;
        } else {
            return Severity.UNASSIGNED;
        }
    }

}
