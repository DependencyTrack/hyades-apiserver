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
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlBatch;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

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
            SELECT COUNT(*)
            FROM "ANALYSIS"
            WHERE "COMPONENT_ID" = :componentId
            AND "SUPPRESSED" IS TRUE
            """)
    long getSuppressedCount(@Bind Long componentId);

    @SqlQuery("""
            SELECT COUNT(*)
            FROM "ANALYSIS"
            WHERE "PROJECT_ID" = :projectId
            AND "COMPONENT_ID" = :componentId
            AND "SUPPRESSED" IS TRUE
            """)
    long getSuppressedCount(@Bind Long projectId, @Bind Long componentId);

    @SqlQuery("""
            SELECT * FROM "ANALYSIS"
            WHERE "PROJECT_ID" = :projectId
            """)
    @GetGeneratedKeys("*")
    @RegisterBeanMapper(Analysis.class)
    List<Analysis> getAnalyses(@Bind Long projectId);
}
