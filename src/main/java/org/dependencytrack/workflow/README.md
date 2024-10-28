Background:

- DT needs workflow capabilities, but a full-blown external engine is overkill
- Already has bare-bones workflow structure, but lacks scheduling and proper observability

Basic idea:

- Workflow + WorkflowStep are the blueprint of a workflow
- Executing a workflow creates WorkflowRun and WorkflowStepRuns for each WorkflowStep
- WorkflowSteps can depend on other WorkflowSteps in their workflow
  - Allows forming of DAGs, enabling parallel execution of steps
- WorkflowSteps are executed by scheduling jobs
  - Alternatively, WorkflowSteps can wait for external events (e.g. vuln analysis completion)
- Failed WorkflowStepRuns can be restarted
- Jobs can also be used outside of workflows
  - Could replace Alpine's event system
- Use PostgreSQL (native SQL!), but allow usage of dedicated DB for workflows and jobs to reduce load on main DB
- (Can we get rid of Kafka if this solution turns out to scale well?)