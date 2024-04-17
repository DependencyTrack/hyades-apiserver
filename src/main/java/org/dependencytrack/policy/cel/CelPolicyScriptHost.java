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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;

import static org.dependencytrack.policy.cel.CelCommonPolicyLibrary.FUNC_COMPARE_AGE;
import static org.dependencytrack.policy.cel.CelCommonPolicyLibrary.FUNC_COMPARE_VERSION_DISTANCE;
import static org.dependencytrack.policy.cel.CelCommonPolicyLibrary.FUNC_DEPENDS_ON;
import static org.dependencytrack.policy.cel.CelCommonPolicyLibrary.FUNC_IS_DEPENDENCY_OF;
import static org.dependencytrack.policy.cel.CelCommonPolicyLibrary.FUNC_IS_EXCLUSIVE_DEPENDENCY_OF;
import static org.dependencytrack.policy.cel.CelCommonPolicyLibrary.FUNC_MATCHES_RANGE;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_COMPONENT;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_PROJECT;
import static org.dependencytrack.policy.cel.definition.CelPolicyTypes.TYPE_VULNERABILITY;
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

    public CelPolicyScriptHost(final AbstractCacheManager cacheManager, final CelPolicyType policyType) {
        this.locks = Striped.lock(128);
        this.cacheManager = cacheManager;
        this.environment = Env.newCustomEnv(
                ProtoTypeRegistry.newRegistry(),
                policyType.envOptions()
        );
    }

    public static synchronized CelPolicyScriptHost getInstance(final CelPolicyType policyType) {
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
    public CelPolicyScript compile(final String scriptSrc, final CacheMode cacheMode) throws ScriptCreateException {
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
            final MultiValuedMap<Type, String> requirements = analyzeRequirements(expr);
            validateVersRanges(expr, source);

            script = new CelPolicyScript(program, requirements);
            if (cacheMode == CacheMode.CACHE) {
                cacheManager.put(scriptDigest, script);
            }
            return script;
        } finally {
            lock.unlock();
        }
    }

    private static MultiValuedMap<Type, String> analyzeRequirements(final CheckedExpr expr) {
        final var visitor = new CelPolicyScriptVisitor(expr.getTypeMapMap());
        visitor.visit(expr.getExpr());

        // Fields that are accessed directly are always a requirement.
        final MultiValuedMap<Type, String> requirements = visitor.getAccessedFieldsByType();

        // Special case for vulnerability severity: The "true" severity may or may not be persisted
        // in the SEVERITY database column. To compute the actual severity, CVSSv2, CVSSv3, and OWASP RR
        // scores may be required. See https://github.com/DependencyTrack/dependency-track/issues/2474
        if (requirements.containsKey(TYPE_VULNERABILITY)
            && requirements.get(TYPE_VULNERABILITY).contains("severity")) {
            requirements.putAll(TYPE_VULNERABILITY, List.of(
                    "cvssv2_base_score",
                    "cvssv3_base_score",
                    "owasp_rr_likelihood_score",
                    "owasp_rr_technical_impact_score",
                    "owasp_rr_business_impact_score"
            ));
        }

        // Custom functions may access certain fields implicitly, in a way that is not visible
        // to the AST visitor. To compensate, we hardcode the functions' requirements here.
        // TODO: This should be restructured to be more generic.
        for (final FunctionSignature functionSignature : visitor.getUsedFunctionSignatures()) {
            switch (functionSignature.function()) {
                case FUNC_DEPENDS_ON, FUNC_IS_DEPENDENCY_OF, FUNC_IS_EXCLUSIVE_DEPENDENCY_OF -> {
                    if (TYPE_PROJECT.equals(functionSignature.targetType())) {
                        requirements.put(TYPE_PROJECT, "uuid");
                    } else if (TYPE_COMPONENT.equals(functionSignature.targetType())) {
                        requirements.put(TYPE_COMPONENT, "uuid");
                    }
                }
                case FUNC_MATCHES_RANGE -> {
                    if (TYPE_PROJECT.equals(functionSignature.targetType())) {
                        requirements.put(TYPE_PROJECT, "version");
                    } else if (TYPE_COMPONENT.equals(functionSignature.targetType())) {
                        requirements.put(TYPE_COMPONENT, "version");
                    }
                }
                case FUNC_COMPARE_VERSION_DISTANCE ->
                        requirements.putAll(TYPE_COMPONENT, List.of("purl", "uuid", "version", "latest_version"));

                case FUNC_COMPARE_AGE -> requirements.putAll(TYPE_COMPONENT, List.of("purl", "published_at"));

            }
        }

        return requirements;
    }

    private static void validateVersRanges(final CheckedExpr expr, final Source source) throws ScriptCreateException {
        final var visitor = new CelPolicyScriptVersValidationVisitor(expr.getSourceInfo().getPositionsMap());
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

        throw new ScriptCreateException("Failed to check script", newIssues(new Errors(source).append(celErrors)));
    }

}
