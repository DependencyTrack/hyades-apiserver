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
package org.dependencytrack.notification;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.apache.commons.codec.digest.DigestUtils;
import org.dependencytrack.notification.proto.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.BomProcessingFailedSubject;
import org.dependencytrack.notification.proto.v1.BomValidationFailedSubject;
import org.dependencytrack.notification.proto.v1.NewPolicyViolationsSummarySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitiesSummarySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerableDependencySubject;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.PolicyViolationAnalysisDecisionChangeSubject;
import org.dependencytrack.notification.proto.v1.PolicyViolationSubject;
import org.dependencytrack.notification.proto.v1.ProjectVulnAnalysisCompleteSubject;
import org.dependencytrack.notification.proto.v1.UserSubject;
import org.dependencytrack.notification.proto.v1.VexConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.dependencytrack.notification.proto.v1.VulnerabilityRetractedSubject;
import org.jspecify.annotations.Nullable;
import org.projectnessie.cel.Env;
import org.projectnessie.cel.Env.AstIssuesTuple;
import org.projectnessie.cel.EnvOption;
import org.projectnessie.cel.Library;
import org.projectnessie.cel.Program;
import org.projectnessie.cel.checker.Decls;
import org.projectnessie.cel.common.types.Err;
import org.projectnessie.cel.common.types.pb.ProtoTypeRegistry;
import org.projectnessie.cel.common.types.ref.Val;
import org.projectnessie.cel.extension.StringsLib;

import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * @since 5.7.0
 */
public final class NotificationFilterScriptHost {

    private static final NotificationFilterScriptHost INSTANCE = new NotificationFilterScriptHost();

    private final Cache<String, Program> cache;
    private final Env environment;

    private NotificationFilterScriptHost() {
        this.cache = Caffeine.newBuilder()
                .maximumSize(256)
                .expireAfterAccess(1, TimeUnit.HOURS)
                .build();
        this.environment = Env.newCustomEnv(
                ProtoTypeRegistry.newRegistry(
                        Notification.getDefaultInstance(),
                        BomConsumedOrProcessedSubject.getDefaultInstance(),
                        BomProcessingFailedSubject.getDefaultInstance(),
                        BomValidationFailedSubject.getDefaultInstance(),
                        NewPolicyViolationsSummarySubject.getDefaultInstance(),
                        NewVulnerabilitiesSummarySubject.getDefaultInstance(),
                        NewVulnerabilitySubject.getDefaultInstance(),
                        NewVulnerableDependencySubject.getDefaultInstance(),
                        PolicyViolationSubject.getDefaultInstance(),
                        PolicyViolationAnalysisDecisionChangeSubject.getDefaultInstance(),
                        VulnerabilityAnalysisDecisionChangeSubject.getDefaultInstance(),
                        ProjectVulnAnalysisCompleteSubject.getDefaultInstance(),
                        VexConsumedOrProcessedSubject.getDefaultInstance(),
                        VulnerabilityRetractedSubject.getDefaultInstance(),
                        UserSubject.getDefaultInstance()),
                List.of(
                        Library.StdLib(),
                        Library.Lib(new StringsLib()),
                        EnvOption.container("org.dependencytrack.notification.v1"),
                        EnvOption.declarations(
                                Decls.newVar("level", Decls.Int),
                                Decls.newVar("scope", Decls.Int),
                                Decls.newVar("group", Decls.Int),
                                Decls.newVar("title", Decls.String),
                                Decls.newVar("content", Decls.String),
                                Decls.newVar("timestamp", Decls.Timestamp),
                                Decls.newVar("subject", Decls.Dyn))));
    }

    public static NotificationFilterScriptHost getInstance() {
        return INSTANCE;
    }

    public Program compile(String expressionSrc) {
        return cache.get(DigestUtils.sha256Hex(expressionSrc), key -> {
            AstIssuesTuple astIssuesTuple = environment.parse(expressionSrc);
            if (astIssuesTuple.hasIssues()) {
                throw new InvalidNotificationFilterExpressionException(
                        "Failed to parse expression",
                        astIssuesTuple.getIssues().getErrors());
            }

            astIssuesTuple = environment.check(astIssuesTuple.getAst());
            if (astIssuesTuple.hasIssues()) {
                throw new InvalidNotificationFilterExpressionException(
                        "Failed to check expression",
                        astIssuesTuple.getIssues().getErrors());
            }

            return environment.program(astIssuesTuple.getAst());
        });
    }

    public boolean evaluate(Program program, Notification notification, @Nullable Object subject) {
        final var args = new HashMap<String, @Nullable Object>(7);
        args.put("level", notification.getLevelValue());
        args.put("scope", notification.getScopeValue());
        args.put("group", notification.getGroupValue());
        args.put("title", notification.getTitle());
        args.put("content", notification.getContent());
        args.put("timestamp", notification.getTimestamp());
        args.put("subject", subject);

        final Val result = program.eval(args).getVal();

        if (Err.isError(result)) {
            throw new IllegalStateException("CEL evaluation failed: " + result);
        }

        return result.convertToNative(Boolean.class);
    }

}
