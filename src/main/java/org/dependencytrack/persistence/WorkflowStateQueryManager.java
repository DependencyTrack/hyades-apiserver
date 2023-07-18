package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.resources.AlpineRequest;
import alpine.server.util.DbUtil;
import org.dependencytrack.model.WorkflowState;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class WorkflowStateQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = Logger.getLogger(WorkflowStateQueryManager.class);

    private static final String PARENT_QUERY = "CTE_WORKFLOW_STATE (ID, PARENT_STEP_ID, STATUS, STEP, TOKEN, STARTED_AT, UPDATED_AT) AS (SELECT ID, PARENT_STEP_ID, STATUS, STEP, TOKEN, STARTED_AT, UPDATED_AT FROM WORKFLOW_STATE ";
    private static final String UNION_ALL = " UNION ALL ";
    private static final String RECURSIVE_QUERY = " SELECT e.ID, e.PARENT_STEP_ID, e.STATUS, e.STEP, e.TOKEN, e.STARTED_AT, e.UPDATED_AT FROM WORKFLOW_STATE e INNER JOIN CTE_WORKFLOW_STATE o ON o.ID = e.PARENT_STEP_ID " + ")";
    private static final String SELECT_QUERY = " SELECT ID, PARENT_STEP_ID, STATUS, STEP, TOKEN, STARTED_AT, UPDATED_AT FROM CTE_WORKFLOW_STATE ";

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

    public List<WorkflowState> getAllWorkflowStatesForParentByToken(UUID token, WorkflowState parentWorkflowState) {
        StringBuilder filterCriteria = new StringBuilder();
        filterCriteria = parentWorkflowState == null ? filterCriteria.append(" WHERE PARENT_STEP_ID IS NULL ") :
                filterCriteria.append(" WHERE PARENT_STEP_ID = ? ");
        filterCriteria = filterCriteria.append(" AND TOKEN = ? ");

        StringBuilder cteQuery = new StringBuilder();
        cteQuery = cteQuery.append(PARENT_QUERY).append(filterCriteria).append(UNION_ALL).append(RECURSIVE_QUERY).append(SELECT_QUERY);

        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet rs = null;
        List<WorkflowState> results = new ArrayList<>();
        try {
            connection = (Connection) pm.getDataStoreConnection();
            if (DbUtil.isMssql() || DbUtil.isOracle()) { // Microsoft SQL Server and Oracle DB already imply the "RECURSIVE" keyword in the "WITH" clause, therefore it is not needed in the query
                preparedStatement = connection.prepareStatement("WITH " + cteQuery);
            } else { // Other Databases need the "RECURSIVE" keyword in the "WITH" clause to correctly execute the query
                preparedStatement = connection.prepareStatement("WITH RECURSIVE " + cteQuery);
            }

            if (parentWorkflowState == null) {
                preparedStatement.setObject(1, token);
            } else {
                preparedStatement.setObject(1, parentWorkflowState.getId());
                preparedStatement.setObject(2, parentWorkflowState.getToken());
            }

            preparedStatement.execute();
            rs = preparedStatement.getResultSet();
            while (rs.next()) {
                WorkflowState workflowState = new WorkflowState();
                workflowState.setId(rs.getLong(1));
                WorkflowState parent = new WorkflowState();
                parent.setId(rs.getLong(2));
                workflowState.setParent(parent);
                workflowState.setStatus(rs.getString(3));
                workflowState.setStep(rs.getString(4));
                workflowState.setToken(rs.getObject(5, UUID.class));
                workflowState.setStartedAt(rs.getDate(6));
                workflowState.setUpdatedAt(rs.getDate(7));
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
}
