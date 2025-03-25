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
package org.dependencytrack.util;

import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.persistence.jdbi.AnalysisDao;
import org.dependencytrack.util.AnalysisCommentFormatter.AnalysisCommentField;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.AnalysisCommentFormatter.formatComment;

public final class AnalysisCommentUtil {

    private AnalysisCommentUtil() { }

    public static boolean makeStateComment(final Analysis analysis, final AnalysisState analysisState, final String commenter) {
        boolean analysisStateChange = false;
        if (analysisState != null && analysisState != analysis.getAnalysisState()) {
            analysisStateChange = true;
            withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                    .makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentField.STATE, analysis.getAnalysisState(), analysisState), commenter));
        }
        return analysisStateChange;
    }

    public static void makeJustificationComment(final Analysis analysis, final AnalysisJustification analysisJustification, final String commenter) {
        if (analysisJustification != null) {
            if (analysis.getAnalysisJustification() == null && AnalysisJustification.NOT_SET != analysisJustification) {
                withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                        .makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentField.JUSTIFICATION, AnalysisJustification.NOT_SET, analysisJustification), commenter));
            } else if (analysis.getAnalysisJustification() != null && analysisJustification != analysis.getAnalysisJustification()) {
                withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                        .makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentField.JUSTIFICATION, analysis.getAnalysisJustification(), analysisJustification), commenter));
            }
        }
    }

    public static void makeAnalysisResponseComment(final Analysis analysis, final AnalysisResponse analysisResponse, final String commenter) {
        if (analysisResponse != null) {
            if (analysis.getAnalysisResponse() == null && analysis.getAnalysisResponse() != analysisResponse) {
                withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                        .makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentField.RESPONSE, AnalysisResponse.NOT_SET, analysisResponse), commenter));
            } else if (analysis.getAnalysisResponse() != null && analysis.getAnalysisResponse() != analysisResponse) {
                withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                        .makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentField.RESPONSE, analysis.getAnalysisResponse(), analysisResponse), commenter));
            }
        }
    }

    public static void makeAnalysisDetailsComment(final Analysis analysis, final String analysisDetails, final String commenter) {
        if (analysisDetails != null && !analysisDetails.equals(analysis.getAnalysisDetails())) {
            withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                    .makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentField.DETAILS, analysis.getAnalysisDetails(), analysisDetails), commenter));
        }
    }

    public static boolean makeAnalysisSuppressionComment(final Analysis analysis, final Boolean suppressed, final String commenter) {
        boolean suppressionChange = false;
        if (suppressed != null && analysis.isSuppressed() != suppressed) {
            suppressionChange = true;
            withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                    .makeAnalysisComment(analysis.getId(), formatComment(AnalysisCommentField.SUPPRESSED, analysis.isSuppressed(), suppressed), commenter));
        }
        return suppressionChange;
    }
}
