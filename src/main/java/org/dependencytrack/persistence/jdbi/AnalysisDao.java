package org.dependencytrack.persistence.jdbi;

import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlBatch;

import java.util.List;

public interface AnalysisDao {

    @SqlBatch("""
            INSERT INTO "ANALYSISCOMMENT"
              ("ANALYSIS_ID", "COMMENT", "COMMENTER", "TIMESTAMP")
            VALUES
              (:analysisId, :comment, :commenter, NOW())
            """)
    void createComments(@Bind List<Long> analysisId, @Bind String commenter, @Bind List<String> comment);

}
