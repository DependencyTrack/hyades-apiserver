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
package org.dependencytrack.policy.cel;

import alpine.common.logging.Logger;
import alpine.server.cache.AbstractCacheManager;
import alpine.server.cache.CacheManager;
import com.google.api.expr.v1alpha1.CheckedExpr;
import com.google.api.expr.v1alpha1.Type;
import com.google.common.util.concurrent.Striped;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections4.MultiValuedMap;
import org.dependencytrack.policy.cel.CelPolicyScriptSpdxExpressionValidationVisitor.SpdxExpressionValidationError;
import org.dependencytrack.policy.cel.CelPolicyScriptVersValidationVisitor.VersValidationError;
import org.dependencytrack.policy.cel.CelPolicyScriptVisitor.FunctionSignature;
import org.projectnessie.cel.Ast;
import org.projectnessie.cel.CEL;
import org.projectnessie.cel.Env;
import org.projectnessie.cel.Env.AstIssuesTuple;
import org.projectnessie.cel.Program;
import org.projectnessie.cel.common.CELError;
import org.projectnessie.cel.common.Errors;
import org.projectnessie.cel.common.Location;
import org.projectnessie.cel.common.Source;
import org.projectnessie.cel.common.types.Err.ErrException;
import org.projectnessie.cel.common.types.pb.ProtoTypeRegistry;
import org.projectnessie.cel.tools.ScriptCreateException;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.stream.Collectors;

import static org.dependencytrack.policy.cel.CelCommonPolicyLibrary.FIELD_EXPANSIONS;
import static org.dependencytrack.policy.cel.CelCommonPolicyLibrary.FUNCTION_FIELD_REQUIREMENTS;
import static org.projectnessie.cel.Issues.newIssues;
import static org.projectnessie.cel.common.Source.newTextSource;

public class CelPolicyScriptHost {

    public enum CacheMode {
        CACHE,
        NO_CACHE
    }

    private static final Logger LOGGER = Logger.getLogger(CelPolicyScriptHost.class);
    private static final ConcurrentHashMap<CelPolicyType, CelPolicyScriptHost> INSTANCES = new ConcurrentHashMap<>();

    private final Striped<Lock> locks;
    private final AbstractCacheManager cacheManager;
    private final Env environment;

    public CelPolicyScriptHost(AbstractCacheManager cacheManager, CelPolicyType policyType) {
        this.locks = Striped.lock(128);
        this.cacheManager = cacheManager;
        this.environment = Env.newCustomEnv(
                ProtoTypeRegistry.newRegistry(),
                policyType.envOptions()
        );
    }

    public static synchronized CelPolicyScriptHost getInstance(CelPolicyType policyType) {
        return INSTANCES.computeIfAbsent(policyType, ignored -> new CelPolicyScriptHost(CacheManager.getInstance(), policyType));
    }

    /**
     * Compile, type-check, ana analyze a given CEL script.
     *
     * @param scriptSrc Source of the script to compile
     * @param cacheMode Whether the {@link CelPolicyScript} shall be cached upon successful compilation
     * @return The compiled {@link CelPolicyScript}
     * @throws ScriptCreateException When compilation, type checking, or analysis failed
     */
    public CelPolicyScript compile(String scriptSrc, CacheMode cacheMode) throws ScriptCreateException {
        final String scriptDigest = DigestUtils.sha256Hex(scriptSrc);

        // Acquire a lock for the SHA256 digest of the script source.
        // It is possible that compilation of the same script will be attempted multiple
        // times concurrently.
        final Lock lock = locks.get(scriptDigest);
        lock.lock();

        try {
            CelPolicyScript script = cacheManager.get(CelPolicyScript.class, scriptDigest);
            if (script != null) {
                return script;
            }

            LOGGER.debug("Compiling script: %s".formatted(scriptSrc));
            AstIssuesTuple astIssuesTuple = environment.parse(scriptSrc);
            if (astIssuesTuple.hasIssues()) {
                throw new ScriptCreateException("Failed to parse script", astIssuesTuple.getIssues());
            }

            final Source source = newTextSource(scriptSrc);

            try {
                astIssuesTuple = environment.check(astIssuesTuple.getAst());
            } catch (ErrException e) {
                // TODO: Bring error message in a more digestible form.
                throw new ScriptCreateException("Failed to check script", newIssues(new Errors(source)
                        .append(Collections.singletonList(
                                new CELError(e, Location.newLocation(1, 1), e.getMessage())
                        ))
                ));
            }
            if (astIssuesTuple.hasIssues()) {
                throw new ScriptCreateException("Failed to check script", astIssuesTuple.getIssues());
            }

            final Ast ast = astIssuesTuple.getAst();
            final Program program = environment.program(ast);
            final var expr = CEL.astToCheckedExpr(ast);
            final var analysis = analyze(expr);
            final Set<String> usedFunctions = analysis.usedFunctions();
            validateVersRanges(expr, source, usedFunctions);
            validateSpdxExpressions(expr, source, usedFunctions);

            script = new CelPolicyScript(program, analysis.requirements());
            if (cacheMode == CacheMode.CACHE) {
                cacheManager.put(scriptDigest, script);
            }
            return script;
        } finally {
            lock.unlock();
        }
    }

    private record AnalysisResult(MultiValuedMap<Type, String> requirements, Set<String> usedFunctions) {
    }

    private static AnalysisResult analyze(CheckedExpr expr) {
        final var visitor = new CelPolicyScriptVisitor(expr.getTypeMapMap());
        visitor.visit(expr.getExpr());

        final MultiValuedMap<Type, String> requirements = visitor.getAccessedFieldsByType();

        for (final var expansion : FIELD_EXPANSIONS.entrySet()) {
            final Type type = expansion.getKey();
            if (!requirements.containsKey(type)) {
                continue;
            }

            for (final var fieldExpansion : expansion.getValue().entrySet()) {
                if (requirements.get(type).contains(fieldExpansion.getKey())) {
                    requirements.putAll(type, fieldExpansion.getValue());
                }
            }
        }

        final Set<FunctionSignature> functionSignatures = visitor.getUsedFunctionSignatures();
        for (final FunctionSignature funcSignature : functionSignatures) {
            final Map<Type, List<String>> funcRequirements =
                    FUNCTION_FIELD_REQUIREMENTS.get(funcSignature.function());
            if (funcRequirements == null) {
                continue;
            }

            final List<String> fields = funcRequirements.get(funcSignature.targetType());
            if (fields != null) {
                requirements.putAll(funcSignature.targetType(), fields);
            }
        }

        final Set<String> usedFunctions = functionSignatures.stream()
                .map(FunctionSignature::function)
                .collect(Collectors.toSet());

        return new AnalysisResult(requirements, usedFunctions);
    }

    private static void validateVersRanges(
            CheckedExpr expr,
            Source source,
            Set<String> usedFunctions) throws ScriptCreateException {
        final var visitor = new CelPolicyScriptVersValidationVisitor(
                expr.getSourceInfo().getPositionsMap(), usedFunctions);
        visitor.visit(expr.getExpr());

        final List<VersValidationError> validationErrors = visitor.getErrors();
        if (validationErrors.isEmpty()) {
            return;
        }

        final List<CELError> celErrors = validationErrors.stream()
                .map(versError -> {
                    final Location location = source.offsetLocation(versError.position());
                    return new CELError(versError.exception(), location, versError.exception().getMessage());
                })
                .toList();

        throw new ScriptCreateException(
                "Failed to check script",
                newIssues(new Errors(source).append(celErrors)));
    }

    private static void validateSpdxExpressions(
            CheckedExpr expr,
            Source source,
            Set<String> usedFunctions) throws ScriptCreateException {
        final var visitor = new CelPolicyScriptSpdxExpressionValidationVisitor(
                expr.getSourceInfo().getPositionsMap(), usedFunctions);
        visitor.visit(expr.getExpr());

        final List<SpdxExpressionValidationError> validationErrors = visitor.getErrors();
        if (validationErrors.isEmpty()) {
            return;
        }

        final List<CELError> celErrors = validationErrors.stream()
                .map(spdxError -> {
                    final Location location = source.offsetLocation(spdxError.position());
                    return new CELError(null, location, spdxError.message());
                })
                .toList();

        throw new ScriptCreateException(
                "Failed to check script",
                newIssues(new Errors(source).append(celErrors)));
    }

}
