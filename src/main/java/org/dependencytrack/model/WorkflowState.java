package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.FetchGroup;
import javax.jdo.annotations.FetchGroups;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Date;
import java.util.UUID;

@PersistenceCapable(table= "WORKFLOW_STATE")
@FetchGroups({
        @FetchGroup(name = "ALL", members = {
                @Persistent(name = "id"),
                @Persistent(name = "parent"),
                @Persistent(name = "token"),
                @Persistent(name = "updatedAt"),
                @Persistent(name = "startedAt"),
                @Persistent(name = "step"),
                @Persistent(name = "status")
        })
})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class WorkflowState implements Serializable {

    public enum FetchGroup {
        ALL
    }

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    private long id;

    // null allowed because first step will have no parent and will be the first step of recursion
    @Persistent
    @Column(name = "PARENT_STEP_ID" , allowsNull = "true")
    private WorkflowState parent;

    @Column(name = "TOKEN", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID token;

    @Persistent
    @Column(name = "STARTED_AT", allowsNull = "true")
    @NotNull
    private Date startedAt;

    @Persistent
    @Column(name = "UPDATED_AT", allowsNull = "true")
    @NotNull
    private Date updatedAt;

    @Persistent
    @Column(name = "STEP", jdbcType = "VARCHAR", length = 64, allowsNull = "false")
    @NotNull
    private String step;

    @Persistent
    @Column(name = "STATUS", jdbcType = "VARCHAR", length = 64, allowsNull = "false")
    @NotNull
    private String status;

    @Persistent
    @Column(name = "FAILURE_REASON", jdbcType = "CLOB", allowsNull = "true")
    private String failureReason;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public WorkflowState getParent() {
        return parent;
    }

    public void setParent(WorkflowState parent) {
        this.parent = parent;
    }

    public UUID getToken() {
        return token;
    }

    public void setToken(UUID token) {
        this.token = token;
    }

    public Date getStartedAt() {
        return startedAt;
    }

    public void setStartedAt(Date startedAt) {
        this.startedAt = startedAt;
    }

    public Date getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Date updatedAt) {
        this.updatedAt = updatedAt;
    }

    public String getStep() {
        return step;
    }

    public void setStep(String step) {
        this.step = step;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getFailureReason() {
        return failureReason;
    }

    public void setFailureReason(String failureReason) {
        this.failureReason = failureReason;
    }
}
