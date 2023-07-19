package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.resources.AlpineRequest;
import alpine.server.util.DbUtil;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class WorkflowStateQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = Logger.getLogger(WorkflowStateQueryManager.class);

    private static final String CTE_WORKFLOW_STATE_QUERY = "CTE_WORKFLOW_STATE (ID,\n" +
            "                                     PARENT_STEP_ID,\n" +
            "                                     STATUS,\n" +
            "                                     STEP,\n" +
            "                                     TOKEN,\n" +
            "                                     STARTED_AT,\n" +
            "                                     UPDATED_AT) AS\n" +
            "  (SELECT ID,\n" +
            "          PARENT_STEP_ID,\n" +
            "          STATUS,\n" +
            "          STEP,\n" +
            "          TOKEN,\n" +
            "          STARTED_AT,\n" +
            "          UPDATED_AT\n" +
            "   FROM WORKFLOW_STATE\n" +
            "   WHERE PARENT_STEP_ID = ?\n" +
            "     AND TOKEN = ?\n" +
            "   UNION ALL SELECT e.ID,\n" +
            "                    e.PARENT_STEP_ID,\n" +
            "                    e.STATUS,\n" +
            "                    e.STEP,\n" +
            "                    e.TOKEN,\n" +
            "                    e.STARTED_AT,\n" +
            "                    e.UPDATED_AT\n" +
            "   FROM WORKFLOW_STATE e\n" +
            "   INNER JOIN CTE_WORKFLOW_STATE o ON o.ID = e.PARENT_STEP_ID)\n" +
            "SELECT ID,\n" +
            "       PARENT_STEP_ID,\n" +
            "       STATUS,\n" +
            "       STEP,\n" +
            "       TOKEN,\n" +
            "       STARTED_AT,\n" +
            "       UPDATED_AT\n" +
            "FROM CTE_WORKFLOW_STATE";


    WorkflowStateQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    WorkflowStateQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    public WorkflowState createWorkflowState(WorkflowState workflowState) {
        final WorkflowState result = persist(workflowState);
        return result;
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
        final Query<WorkflowState> query = pm.newQuery(WorkflowState.class, "this.token == :token && this.step == step");
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
    public List<WorkflowState> getAllWorkflowStatesForParent(WorkflowState parentWorkflowState) {

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

            preparedStatement.setObject(1, parentWorkflowState.getId());
            preparedStatement.setObject(2, parentWorkflowState.getToken());

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
                workflowState.setToken(rs.getObject("TOKEN", UUID.class));
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

    public int updateAllWorkflowStatesForParent(WorkflowState parentWorkflowState, WorkflowStatus transientStatus) {

        if(parentWorkflowState == null || parentWorkflowState.getId() <= 0 ) {
            throw new IllegalArgumentException("Parent workflow state cannot be null and id of parent cannot be missing to get workflow states hierarchically");
        }

        Connection connection = null;
        Statement statement = null;
        try {
            connection = (Connection) pm.getDataStoreConnection();

            //Using query string because binding is not working in preparedStatement for STATUS field
            //There should not be risk of RCE because of constraint on db which will only let a
            //valid enum value in STATUS field
            String query = "UPDATE \"WORKFLOW_STATE\" \n" +
                    "SET \"STATUS\" = " +"\'" + transientStatus.toString() +"\'" + "\n" +
                    "WHERE \"ID\" IN \n" +
                    " (WITH RECURSIVE \"CTE_WORKFLOW_STATE\" (\"ID\") AS \n" +
                    "       (SELECT \"ID\" \n" +
                    "        FROM public.\"WORKFLOW_STATE\"\n" +
                    "        WHERE \"PARENT_STEP_ID\" = " +"\'" + parentWorkflowState.getId() +"\'" +"\n" +
                    "          AND \"TOKEN\" = "  +"\'" + parentWorkflowState.getToken() +"\'" + "\n" +
                    "        UNION ALL SELECT e.\"ID\" \n" +
                    "        FROM \"WORKFLOW_STATE\" e\n" +
                    "        INNER JOIN \"CTE_WORKFLOW_STATE\" o ON o.\"ID\" = e.\"PARENT_STEP_ID\") SELECT \"ID\"\n" +
                    "     FROM \"CTE_WORKFLOW_STATE\"); ";

            statement = connection.createStatement();
            return statement.executeUpdate(query);
        } catch (Exception ex) {
            LOGGER.error("error in executing workflow state cte query to update states", ex);
            throw new RuntimeException(ex);
        } finally {
            DbUtil.close(statement);
            DbUtil.close(connection);
        }
    }
}
