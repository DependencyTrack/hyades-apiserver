package org.dependencytrack.policy.cel;

import alpine.common.logging.Logger;
import alpine.server.cache.CacheManager;
import com.google.api.expr.v1alpha1.CheckedExpr;
import com.google.api.expr.v1alpha1.Type;
import com.google.common.util.concurrent.Striped;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections4.MultiValuedMap;
import org.projectnessie.cel.Ast;
import org.projectnessie.cel.CEL;
import org.projectnessie.cel.Env;
import org.projectnessie.cel.Env.AstIssuesTuple;
import org.projectnessie.cel.Library;
import org.projectnessie.cel.Program;
import org.projectnessie.cel.common.CELError;
import org.projectnessie.cel.common.Errors;
import org.projectnessie.cel.common.Location;
import org.projectnessie.cel.common.types.Err.ErrException;
import org.projectnessie.cel.common.types.pb.ProtoTypeRegistry;
import org.projectnessie.cel.tools.ScriptCreateException;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.locks.Lock;

import static org.projectnessie.cel.Issues.newIssues;
import static org.projectnessie.cel.common.Source.newTextSource;

public class CelPolicyScriptHost {

    private static final Logger LOGGER = Logger.getLogger(CelPolicyScriptHost.class);
    private static CelPolicyScriptHost INSTANCE;

    private final Striped<Lock> locks;
    private final CacheManager cacheManager;
    private final Env environment;

    CelPolicyScriptHost(final CacheManager cacheManager) {
        this.locks = Striped.lock(128);
        this.cacheManager = cacheManager;
        this.environment = Env.newCustomEnv(
                ProtoTypeRegistry.newRegistry(),
                List.of(
                        Library.StdLib(),
                        Library.Lib(new CelPolicyLibrary())
                )
        );
    }

    public static synchronized CelPolicyScriptHost getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new CelPolicyScriptHost(CacheManager.getInstance());
        }

        return INSTANCE;
    }

    public CelPolicyScript compile(final String scriptSrc) throws ScriptCreateException {
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

            try {
                astIssuesTuple = environment.check(astIssuesTuple.getAst());
            } catch (ErrException e) {
                // TODO: Bring error message in a more digestible form.
                throw new ScriptCreateException("Failed to check script", newIssues(new Errors(newTextSource(scriptSrc))
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
            final MultiValuedMap<Type, String> requirements = analyzeRequirements(CEL.astToCheckedExpr(ast));

            script = new CelPolicyScript(program, requirements);
            cacheManager.put(scriptDigest, script);
            return script;
        } finally {
            lock.unlock();
        }
    }

    private static MultiValuedMap<Type, String> analyzeRequirements(final CheckedExpr expr) {
        final var visitor = new CelPolicyScriptVisitor(expr.getTypeMapMap());
        visitor.visit(expr.getExpr());
        return visitor.getAccessedFieldsByType();
    }

}
