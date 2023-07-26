package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.resources.AlpineRequest;
import alpine.server.util.DbUtil;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.Transaction;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class WorkflowStateQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = Logger.getLogger(WorkflowStateQueryManager.class);

    private static final String CTE_WORKFLOW_STATE_QUERY = """
            
            "CTE_WORKFLOW_STATE" ("ID",
                       "PARENT_STEP_ID",
                       "STATUS",
                       "STEP",
                       "TOKEN",
                       "STARTED_AT",
                       "UPDATED_AT") AS
              (SELECT "ID",
                      "PARENT_STEP_ID",
                      "STATUS",
                      "STEP",
                      "TOKEN",
                      "STARTED_AT",
                      "UPDATED_AT"
               FROM "WORKFLOW_STATE"
               WHERE "PARENT_STEP_ID" = ?
                 AND "TOKEN" = ?
               UNION ALL SELECT "e"."ID",
                                "e"."PARENT_STEP_ID",
                                "e"."STATUS",
                                "e"."STEP",
                                "e"."TOKEN",
                                "e"."STARTED_AT",
                                "e"."UPDATED_AT"
               FROM "WORKFLOW_STATE" "e"
               INNER JOIN "CTE_WORKFLOW_STATE" "o" ON "o"."ID" = "e"."PARENT_STEP_ID")
            SELECT "ID",
                   "PARENT_STEP_ID",
                   "STATUS",
                   "STEP",
                   "TOKEN",
                   "STARTED_AT",
                   "UPDATED_AT"
            FROM "CTE_WORKFLOW_STATE"
            
            """;
    public static final String UPDATE_WORKFLOW_STATES_QUERY = """
            
            UPDATE "WORKFLOW_STATE"
            SET "STATUS" = ?,
            "UPDATED_AT" = ?
            WHERE "ID" IN
                (WITH RECURSIVE "CTE_WORKFLOW_STATE" ("ID") AS
                   (SELECT "ID"
                    FROM "WORKFLOW_STATE"
                    WHERE "PARENT_STEP_ID" = ?
                      AND "TOKEN" = ?
                    UNION ALL SELECT "e"."ID"
                    FROM "WORKFLOW_STATE" AS "e"
                    INNER JOIN "CTE_WORKFLOW_STATE" AS "o" ON "o"."ID" = "e"."PARENT_STEP_ID") SELECT "ID"
                 FROM "CTE_WORKFLOW_STATE")
            
            """;

    WorkflowStateQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    WorkflowStateQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    public WorkflowState getWorkflowState(long id) {
        final Query<WorkflowState> query = pm.newQuery(WorkflowState.class, "id == :id");
        query.setRange(0, 1);
        return singleResult(query.execute(id));
    }

    public WorkflowState updateWorkflowState(WorkflowState transientWorkflowState) {
        //update fields
        WorkflowState workflowState = getObjectById(WorkflowState.class, transientWorkflowState.getId());
        if (workflowState != null) {
            workflowState.setStatus(transientWorkflowState.getStatus());
            workflowState.setUpdatedAt(transientWorkflowState.getUpdatedAt());
            workflowState.setFailureReason(transientWorkflowState.getFailureReason());
            return persist(workflowState);
        }
        return null;
    }

    public void deleteWorkflowState(WorkflowState workflowState) {
        delete(workflowState);
    }

    public List<WorkflowState> getAllWorkflowStatesForAToken(UUID token) {
        final Query<WorkflowState> query = pm.newQuery(WorkflowState.class, "this.token == :token");
        query.setParameters(token);
        return query.executeList();
    }

    public WorkflowState getWorkflowStateByTokenAndStep(UUID token, WorkflowStep step) {
        final Query<WorkflowState> query = pm.newQuery(WorkflowState.class, "this.token == :token && this.step == :step");
        query.setParameters(token, step);
        return query.executeUnique();
    }

    /**
     * Returns descendants of parent workflow state
     * @param parentWorkflowState whose descendants we want to fetch
     * @return the list of WorkflowStates
     *
     * Returned workflow states will only have id field in their parent workflow state field
     * This is because method uses CTE query which cannot return the associated parent fields other than id
     */
    public List<WorkflowState> getAllDescendantWorkflowStatesOfParent(WorkflowState parentWorkflowState) {

        if(parentWorkflowState == null || parentWorkflowState.getId() <= 0 ) {
            throw new IllegalArgumentException("Parent workflow state cannot be null and id of parent cannot be missing to get workflow states hierarchically");
        }

        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet rs = null;
        List<WorkflowState> results = new ArrayList<>();
        try {
            connection = (Connection) pm.getDataStoreConnection();
            if (DbUtil.isMssql() || DbUtil.isOracle()) { // Microsoft SQL Server and Oracle DB already imply the "RECURSIVE" keyword in the "WITH" clause, therefore it is not needed in the query
                preparedStatement = connection.prepareStatement("WITH " + CTE_WORKFLOW_STATE_QUERY);
            } else { // Other Databases need the "RECURSIVE" keyword in the "WITH" clause to correctly execute the query
                preparedStatement = connection.prepareStatement("WITH RECURSIVE " + CTE_WORKFLOW_STATE_QUERY);
            }

            preparedStatement.setLong(1, parentWorkflowState.getId());
            preparedStatement.setString(2, parentWorkflowState.getToken().toString());

            preparedStatement.execute();
            rs = preparedStatement.getResultSet();
            while (rs.next()) {
                WorkflowState workflowState = new WorkflowState();
                workflowState.setId(rs.getLong("ID"));
                WorkflowState parent = new WorkflowState();
                parent.setId(rs.getLong("PARENT_STEP_ID"));
                workflowState.setParent(parent);
                //check on db for enum values so value returned will be a valid string
                workflowState.setStatus(WorkflowStatus.valueOf(rs.getString("STATUS")));
                workflowState.setStep(WorkflowStep.valueOf(rs.getString("STEP")));
                workflowState.setToken(UUID.fromString(rs.getString("TOKEN")));
                workflowState.setStartedAt(rs.getDate("STARTED_AT"));
                workflowState.setUpdatedAt(rs.getDate("UPDATED_AT"));
                results.add(workflowState);
            }

        } catch (Exception ex) {
            LOGGER.error("error in executing workflow state cte query", ex);
            throw new RuntimeException(ex);
        } finally {
            DbUtil.close(rs);
            DbUtil.close(preparedStatement);
            DbUtil.close(connection);
        }
        return results;
    }

    public int updateAllDescendantStatesOfParent(WorkflowState parentWorkflowState, WorkflowStatus transientStatus, Date updatedAt) {

        if(parentWorkflowState == null || parentWorkflowState.getId() <= 0 ) {
            throw new IllegalArgumentException("Parent workflow state cannot be null and id of parent cannot be missing to get workflow states hierarchically");
        }

        Connection connection = null;
        PreparedStatement preparedStatement = null;
        try {
            connection = (Connection) pm.getDataStoreConnection();

            preparedStatement = connection.prepareStatement(UPDATE_WORKFLOW_STATES_QUERY);
            preparedStatement.setString(1, transientStatus.name());
            preparedStatement.setTimestamp(2, new java.sql.Timestamp(updatedAt.getTime()));
            preparedStatement.setLong(3, parentWorkflowState.getId());
            preparedStatement.setString(4, parentWorkflowState.getToken().toString());

            return preparedStatement.executeUpdate();
        } catch (Exception ex) {
            LOGGER.error("error in executing workflow state cte query to update states", ex);
            throw new RuntimeException(ex);
        } finally {
            DbUtil.close(preparedStatement);
            DbUtil.close(connection);
        }
    }

    public void createWorkflowSteps(UUID token) {
        final Transaction trx = pm.currentTransaction();
        try {
            trx.begin();
            WorkflowState consumptionState = new WorkflowState();
            consumptionState.setToken(token);
            consumptionState.setStep(WorkflowStep.BOM_CONSUMPTION);
            consumptionState.setStatus(WorkflowStatus.PENDING);
            WorkflowState parent = pm.makePersistent(consumptionState);

            WorkflowState processingState = new WorkflowState();
            processingState.setParent(parent);
            processingState.setToken(token);
            processingState.setStep(WorkflowStep.BOM_PROCESSING);
            processingState.setStatus(WorkflowStatus.PENDING);
            WorkflowState processingParent = pm.makePersistent(processingState);

            WorkflowState vulnAnalysisState = new WorkflowState();
            vulnAnalysisState.setParent(processingParent);
            vulnAnalysisState.setToken(token);
            vulnAnalysisState.setStep(WorkflowStep.VULN_ANALYSIS);
            vulnAnalysisState.setStatus(WorkflowStatus.PENDING);
            pm.makePersistent(vulnAnalysisState);
            trx.commit();
        } finally {
            if (trx.isActive()) {
                trx.rollback();
            }
        }
    }
}
