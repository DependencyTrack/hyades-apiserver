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

import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.util.AnalysisCommentFormatter;
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.DefineNamedBindings;
import org.jdbi.v3.sqlobject.statement.SqlBatch;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.List;

import static org.dependencytrack.util.AnalysisCommentFormatter.formatComment;

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

    @SqlQuery("""
            SELECT *
            FROM "ANALYSIS"
            WHERE "COMPONENT_ID" = :componentId
            AND "VULNERABILITY_ID" = :vulnId
            LIMIT 1
            """)
    @RegisterBeanMapper(Analysis.class)
    Analysis getAnalysis(@Bind long componentId, @Bind long vulnId);

    @SqlQuery("""
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
            RETURNING *
            """)
    @DefineNamedBindings
    @RegisterBeanMapper(Analysis.class)
    Analysis makeAnalysis(@Bind long projectId, @Bind long componentId, @Bind long vulnId, @Bind AnalysisState state,
                          @Bind AnalysisJustification justification, @Bind AnalysisResponse response,
                          @Bind String details, @Bind boolean suppressed);

    default boolean makeStateComment(final Analysis analysis, final AnalysisState analysisState, final String commenter) {
        boolean analysisStateChange = false;
        if (analysisState != null && analysisState != analysis.getState()) {
            analysisStateChange = true;
            makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentFormatter.AnalysisCommentField.STATE, analysis.getState(), analysisState), commenter);
        }
        return analysisStateChange;
    }

    default void makeJustificationComment(final Analysis analysis, final AnalysisJustification analysisJustification, final String commenter) {
        if (analysisJustification != null) {
            if (analysis.getJustification() == null && AnalysisJustification.NOT_SET != analysisJustification) {
                makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentFormatter.AnalysisCommentField.JUSTIFICATION, AnalysisJustification.NOT_SET, analysisJustification), commenter);
            } else if (analysis.getJustification() != null && analysisJustification != analysis.getJustification()) {
                makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentFormatter.AnalysisCommentField.JUSTIFICATION, analysis.getJustification(), analysisJustification), commenter);
            }
        }
    }

    default void makeAnalysisResponseComment(final Analysis analysis, final AnalysisResponse analysisResponse, final String commenter) {
        if (analysisResponse != null) {
            if (analysis.getResponse() == null && analysis.getResponse() != analysisResponse) {
                makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentFormatter.AnalysisCommentField.RESPONSE, AnalysisResponse.NOT_SET, analysisResponse), commenter);
            } else if (analysis.getResponse() != null && analysis.getResponse() != analysisResponse) {
                makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentFormatter.AnalysisCommentField.RESPONSE, analysis.getResponse(), analysisResponse), commenter);
            }
        }
    }

    default void makeAnalysisDetailsComment(final Analysis analysis, final String analysisDetails, final String commenter) {
        if (analysisDetails != null && !analysisDetails.equals(analysis.getDetails())) {
            makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentFormatter.AnalysisCommentField.DETAILS, analysis.getDetails(), analysisDetails), commenter);
        }
    }

    default boolean makeAnalysisSuppressionComment(final Analysis analysis, final Boolean suppressed, final String commenter) {
        boolean suppressionChange = false;
        if (suppressed != null && analysis.isSuppressed() != suppressed) {
            suppressionChange = true;
            makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentFormatter.AnalysisCommentField.SUPPRESSED, analysis.isSuppressed(), suppressed), commenter);
        }
        return suppressionChange;
    }
}
