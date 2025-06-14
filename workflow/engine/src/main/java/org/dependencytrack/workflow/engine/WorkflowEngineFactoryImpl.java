package org.dependencytrack.workflow.engine;

import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowEngineConfig;
import org.dependencytrack.workflow.engine.api.WorkflowEngineFactory;

public class WorkflowEngineFactoryImpl implements WorkflowEngineFactory {

    @Override
    public WorkflowEngine create(final WorkflowEngineConfig config) {
        return new WorkflowEngineImpl(config);
    }

}
