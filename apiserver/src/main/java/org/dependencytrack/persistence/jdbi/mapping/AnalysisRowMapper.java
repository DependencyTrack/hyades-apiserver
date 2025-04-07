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

import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class AnalysisRowMapper implements RowMapper<Analysis> {

    @Override
    public Analysis map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final var analysis = new Analysis();
        maybeSet(rs, "ID", ResultSet::getLong, analysis::setId);
        maybeSet(rs, "COMPONENT_ID", ResultSet::getLong, value -> {
            final var component = new Component();
            component.setId(value);
            analysis.setComponent(component);
        });
        maybeSet(rs, "VULNERABILITY_ID", ResultSet::getLong, value -> {
            final var vuln = new Vulnerability();
            vuln.setId(value);
            analysis.setVulnerability(vuln);
        });
        maybeSet(rs, "STATE", ResultSet::getString, value -> analysis.setAnalysisState(AnalysisState.valueOf(value)));
        maybeSet(rs, "JUSTIFICATION", ResultSet::getString, value -> analysis.setAnalysisJustification(AnalysisJustification.valueOf(value)));
        maybeSet(rs, "RESPONSE", ResultSet::getString, value -> analysis.setAnalysisResponse(AnalysisResponse.valueOf(value)));
        maybeSet(rs, "DETAILS", ResultSet::getString, analysis::setAnalysisDetails);
        maybeSet(rs, "SUPPRESSED", ResultSet::getBoolean, analysis::setSuppressed);
        maybeSet(rs, "SEVERITY", ResultSet::getString, value -> analysis.setSeverity(Severity.valueOf(value)));
        maybeSet(rs, "CVSSV2VECTOR", ResultSet::getString, analysis::setCvssV2Vector);
        maybeSet(rs, "CVSSV2SCORE", ResultSet::getBigDecimal, analysis::setCvssV2Score);
        maybeSet(rs, "CVSSV3VECTOR", ResultSet::getString, analysis::setCvssV3Vector);
        maybeSet(rs, "CVSSV3SCORE", ResultSet::getBigDecimal, analysis::setCvssV3Score);
        maybeSet(rs, "OWASPVECTOR", ResultSet::getString, analysis::setOwaspVector);
        maybeSet(rs, "OWASPSCORE", ResultSet::getBigDecimal, analysis::setOwaspScore);
        return analysis;
    }

}
