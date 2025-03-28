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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.DefineNamedBindings;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlBatch;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.util.List;

public interface AnalysisDao {

    @SqlBatch("""
            INSERT INTO "ANALYSISCOMMENT"
              ("ANALYSIS_ID", "COMMENT", "COMMENTER", "TIMESTAMP")
            VALUES
              (:analysisId, :comment, :commenter, NOW())
            """)
    void createComments(@Bind List<Long> analysisId, @Bind String commenter, @Bind List<String> comment);

    @SqlQuery("""
            INSERT INTO "ANALYSISCOMMENT"
              ("ANALYSIS_ID", "COMMENT", "COMMENTER", "TIMESTAMP")
            VALUES
              (:analysisId, :comment, :commenter, NOW())
            RETURNING *
            """)
    @RegisterBeanMapper(AnalysisComment.class)
    AnalysisComment createComment(@Bind long analysisId, String comment, String commenter);

    default AnalysisComment makeAnalysisComment(long analysisId, String comment, String commenter) {
        if (comment == null) {
            return null;
        }
        return createComment(analysisId, comment, commenter);
    }

    @SqlUpdate("""
            INSERT INTO "ANALYSIS"
               ("PROJECT_ID", "COMPONENT_ID", "VULNERABILITY_ID", "STATE", "JUSTIFICATION", "RESPONSE", "DETAILS", "SUPPRESSED")
            VALUES
               (:projectId, :componentId, :vulnId,
               COALESCE(:state, 'NOT_SET'),
               :justification, :response, :details, :suppressed)
            ON CONFLICT ("PROJECT_ID", "COMPONENT_ID", "VULNERABILITY_ID") DO UPDATE
            SET
               "SUPPRESSED" = :suppressed
               <#if state>
                    , "STATE" = :state
               </#if>
               <#if justification>
                    , "JUSTIFICATION" = :justification
               </#if>
               <#if response>
                    , "RESPONSE" = :response
               </#if>
               <#if details>
                    , "DETAILS" = :details
               </#if>
            RETURNING "ID"
            """)
    @GetGeneratedKeys("ID")
    @DefineNamedBindings
    Long makeAnalysis(@Bind long projectId, @Bind long componentId, @Bind long vulnId, @Bind AnalysisState state,
                          @Bind AnalysisJustification justification, @Bind AnalysisResponse response,
                          @Bind String details, @Bind boolean suppressed);
}
